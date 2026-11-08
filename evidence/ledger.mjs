import { verifyReceipt } from '../shield/shield.mjs';

const FULL_SHA = /^[0-9a-f]{40}$/i;
const SHA256 = /^[0-9a-f]{64}$/i;
const STABLE_ID = /^[A-Z][A-Z0-9_-]{2,127}$/;

export const RECEIPT_STATES = Object.freeze([
  'verified', 'inferred', 'unknown', 'blocked', 'failed', 'stale',
]);

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

function same(left, right) {
  return JSON.stringify(stable(left ?? null)) === JSON.stringify(stable(right ?? null));
}

function assertIso(value, name) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) {
    throw new Error(`${name} must be an ISO-compatible timestamp`);
  }
}

export function assertEvidenceIdentity(identity) {
  if (!identity?.source) throw new Error('identity.source is required');
  const source = identity.source;
  if (!String(source.repository ?? '').trim()) throw new Error('identity.source.repository is required');
  if (!String(source.branch ?? '').trim()) throw new Error('identity.source.branch is required');
  if (!FULL_SHA.test(String(source.commitSha ?? ''))) {
    throw new Error('identity.source.commitSha must be a full 40-character Git SHA');
  }
  if (source.canonicalRemote !== undefined && !String(source.canonicalRemote).trim()) {
    throw new Error('identity.source.canonicalRemote must be non-empty when present');
  }

  if (identity.runtime !== undefined) {
    if (!String(identity.runtime.environment ?? '').trim()) throw new Error('identity.runtime.environment is required');
    if (!String(identity.runtime.buildId ?? '').trim()) throw new Error('identity.runtime.buildId is required');
    if (identity.runtime.deploymentUrl !== undefined && !/^https:\/\//i.test(identity.runtime.deploymentUrl)) {
      throw new Error('identity.runtime.deploymentUrl must use HTTPS when present');
    }
  }

  if (identity.dependency !== undefined) {
    if (!String(identity.dependency.lockfilePath ?? '').trim()) throw new Error('identity.dependency.lockfilePath is required');
    if (!SHA256.test(String(identity.dependency.lockfileSha256 ?? ''))) {
      throw new Error('identity.dependency.lockfileSha256 must be a 64-character SHA-256 digest');
    }
    if (!String(identity.dependency.packageManager ?? '').trim()) throw new Error('identity.dependency.packageManager is required');
  }
}

export function assertEvidenceReceipt(receipt) {
  if (!STABLE_ID.test(String(receipt?.id ?? ''))) throw new Error('receipt.id must be an uppercase stable identifier');
  if (!STABLE_ID.test(String(receipt?.findingId ?? ''))) throw new Error('receipt.findingId must be an uppercase stable identifier');
  if (!String(receipt?.check ?? '').trim()) throw new Error('receipt.check is required');
  if (!RECEIPT_STATES.includes(receipt?.state)) throw new Error('receipt.state is invalid');
  if (!String(receipt?.summary ?? '').trim()) throw new Error('receipt.summary is required');
  assertIso(receipt.observedAt, 'receipt.observedAt');
  assertEvidenceIdentity(receipt.identity);
  if (!Array.isArray(receipt.evidenceRefs)) throw new Error('receipt.evidenceRefs must be an array');
  if (receipt.state === 'verified' && receipt.evidenceRefs.length === 0) {
    throw new Error('verified receipts require at least one evidence reference');
  }
  if (receipt.state === 'stale' && (!Array.isArray(receipt.invalidatedBy) || receipt.invalidatedBy.length === 0)) {
    throw new Error('stale receipts require invalidation reasons');
  }
  if (receipt.authority?.level !== 'evidence_only' || receipt.authority?.canAuthorize !== false) {
    throw new Error('security evidence cannot self-authorize');
  }
}

export function createEvidenceReceipt({
  id,
  findingId,
  check,
  state,
  observedAt,
  identity,
  summary,
  evidenceRefs = [],
  invalidatedBy = [],
}) {
  const receipt = Object.freeze({
    schema: 'protect-me/evidence-receipt@v1',
    id,
    findingId,
    check,
    state,
    observedAt,
    identity: stable(identity),
    summary,
    evidenceRefs: [...evidenceRefs],
    invalidatedBy: [...invalidatedBy],
    authority: { level: 'evidence_only', canAuthorize: false },
  });
  assertEvidenceReceipt(receipt);
  return receipt;
}

export function evaluateStaleness(receipt, currentIdentity) {
  assertEvidenceReceipt(receipt);
  assertEvidenceIdentity(currentIdentity);
  const invalidatedBy = [];
  if (!same(receipt.identity.source, currentIdentity.source)) invalidatedBy.push('source_identity_changed');
  if (!same(receipt.identity.dependency, currentIdentity.dependency)) invalidatedBy.push('dependency_identity_changed');
  if (!same(receipt.identity.runtime, currentIdentity.runtime)) invalidatedBy.push('runtime_identity_changed');
  return Object.freeze({
    state: invalidatedBy.length ? 'stale' : receipt.state,
    invalidatedBy,
  });
}

export function invalidateIfStale(receipt, currentIdentity, observedAt) {
  const result = evaluateStaleness(receipt, currentIdentity);
  if (result.state !== 'stale') return receipt;
  assertIso(observedAt, 'observedAt');
  return createEvidenceReceipt({
    ...receipt,
    state: 'stale',
    observedAt,
    identity: receipt.identity,
    invalidatedBy: result.invalidatedBy,
  });
}

// Receipts are history: for each (findingId, check) only the most recent one
// decides. Ties at the same timestamp resolve to the worst state, so a newer
// pass supersedes an old failure but a simultaneous failure is never hidden.
const STATE_SEVERITY = { verified: 0, inferred: 1, unknown: 2, stale: 3, blocked: 4, failed: 5 };
export function latestReceipts(receipts) {
  const latest = new Map();
  for (const receipt of receipts) {
    const key = `${receipt.findingId}\u0000${receipt.check}`;
    const prev = latest.get(key);
    const t = Date.parse(receipt.observedAt);
    const pt = prev ? Date.parse(prev.observedAt) : -Infinity;
    if (!prev || t > pt || (t === pt && (STATE_SEVERITY[receipt.state] ?? 9) > (STATE_SEVERITY[prev.state] ?? 9))) {
      latest.set(key, receipt);
    }
  }
  return [...latest.values()];
}

export function canCandidateProceed(receipts, requiredChecks, currentIdentity) {
  assertEvidenceIdentity(currentIdentity);
  const seenIds = new Set();
  for (const receipt of receipts) {
    assertEvidenceReceipt(receipt);
    if (seenIds.has(receipt.id)) throw new Error(`duplicate receipt id: ${receipt.id}`);
    seenIds.add(receipt.id);
  }
  const current = latestReceipts(receipts);
  return requiredChecks.every((check) => current.some((receipt) => {
    const freshness = evaluateStaleness(receipt, currentIdentity);
    return receipt.check === check && receipt.state === 'verified' && freshness.state !== 'stale';
  }));
}

export function isGovernedActionEligible({ receipts, requiredChecks, currentIdentity, authorization }) {
  if (!canCandidateProceed(receipts, requiredChecks, currentIdentity)) return false;
  if (latestReceipts(receipts).some((receipt) => {
    const freshness = evaluateStaleness(receipt, currentIdentity);
    return freshness.state === 'stale' || ['failed', 'blocked', 'unknown'].includes(receipt.state);
  })) return false;

  if (!authorization || authorization.kind !== 'founder_approval') return false;
  if (!String(authorization.approvalId ?? '').trim()) return false;
  if (receipts.some((receipt) => receipt.id === authorization.approvalId)) return false;
  if (authorization.repository !== currentIdentity.source.repository) return false;
  if (String(authorization.commitSha ?? '').toLowerCase() !== currentIdentity.source.commitSha.toLowerCase()) return false;
  return true;
}

export async function shieldObservationToReceipt(observation, identity, observedAt, secret = null) {
  if (!observation?.receipt || !observation?.event) throw new Error('shield observation requires event and receipt');
  assertEvidenceIdentity(identity);
  assertIso(observedAt, 'observedAt');
  const authenticated = observation.receiptKind === 'hmac-sha256';
  if (!['hmac-sha256', 'sha256-unauthenticated'].includes(observation.receiptKind)
    || (authenticated && (typeof secret !== 'string' || !secret))
    || !(await verifyReceipt(observation, authenticated ? secret : null))) {
    throw new Error('SHIELD_OBSERVATION_SIGNATURE_UNVERIFIED');
  }
  const suffix = String(observation.receipt).slice(0, 16).toUpperCase();
  return createEvidenceReceipt({
    id: `SHIELD-${suffix}`,
    findingId: `SEC-${suffix}`,
    check: 'shield_event',
    state: authenticated ? 'verified' : 'inferred',
    observedAt,
    identity,
    summary: `Shield observed ${String(observation.event.verdict ?? 'UNKNOWN')} on ${String(observation.event.service ?? 'unknown-service')}.`,
    evidenceRefs: [`shield:${observation.receipt}`],
  });
}
