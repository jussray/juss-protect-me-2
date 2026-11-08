// Source-only server signal adapter: HMAC evidence -> passive incident observations.
// Opt-in consumer wiring must supply a server-owned queue and provenance. This is
// not a public ingestion endpoint, a durable collector or containment authority.
import { assertEvidenceIdentity, createEvidenceReceipt, shieldObservationToReceipt } from '../evidence/ledger.mjs';
import { INCIDENT_SCHEMA } from './incident-correlation.mjs';

const encoder = new TextEncoder();
const SERVICE_RE = /^[a-z][a-z0-9-]{2,63}$/;
const OPAQUE_SHA = /^[a-f0-9]{64}$/;

function hex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((k) => [k, sorted(value[k])]));
  }
  return value;
}
function requireSecret(value) {
  if (typeof value !== 'string' || value.length < 16) throw new TypeError('INCIDENT_SIGNING_SECRET_UNAVAILABLE');
}
function randomRef(prefix) {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return prefix + '_' + hex(bytes).toUpperCase();
}
async function signer(secret) {
  return crypto.subtle.importKey('raw', encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

/**
 * Only trusted server code may hold this bridge. Never expose a route that signs
 * client-submitted events or accepts client-controlled timestamps/actor IDs.
 * Queue acceptance is NOT a verified consumer, independent review or deployment.
 */
export function createIncidentSignalBridge({ service, identity, shieldSecret, signingSecret, sink, clock = () => new Date().toISOString() } = {}) {
  if (typeof service !== 'string' || !SERVICE_RE.test(service)) throw new TypeError('INCIDENT_INVALID_SERVICE');
  assertEvidenceIdentity(identity);
  requireSecret(shieldSecret);
  requireSecret(signingSecret);
  if (shieldSecret === signingSecret) throw new TypeError('INCIDENT_KEYS_MUST_BE_SEPARATE');
  if (!sink || typeof sink.send !== 'function' || typeof clock !== 'function') {
    throw new TypeError('INCIDENT_DURABLE_SINK_REQUIRED');
  }

  async function publish(event, evidenceReceipt) {
    const key = await signer(signingSecret);
    const receipt = hex(await crypto.subtle.sign('HMAC', key, encoder.encode(JSON.stringify(sorted(event)))));
    const envelope = Object.freeze({
      schema: 'protect-me/incident-signal-envelope@v1',
      observation: Object.freeze({ event: Object.freeze(event), receipt, receiptKind: 'hmac-sha256' }),
      evidenceReceipt,
      authority: Object.freeze({ level: 'evidence_only', canAuthorize: false }),
    });
    await sink.send(envelope);
    // The sink accepted an envelope, not proof that an incident was reviewed.
    return Object.freeze({ queued: true, evidenceRef: event.evidenceRef, canAuthorize: false });
  }

  async function onShieldAttempt(observation) {
    if (observation?.transportAuthority?.canAuthorize !== false
      || observation?.event?.service !== service
      || !['PROBE', 'AUTOMATION', 'CLAIMED_CRAWLER'].includes(observation?.event?.verdict)
      || observation?.event?.identity?.verifiedBot !== false
      || !OPAQUE_SHA.test(observation?.event?.identity?.actor ?? '')
      || observation?.event?.pathname !== '[redacted]'
      || observation?.event?.identity?.userAgent !== null) {
      throw new TypeError('INCIDENT_UNTRUSTED_SHIELD_SOURCE');
    }
    const observedAt = clock();
    const signedSource = await shieldObservationToReceipt(observation, identity, observedAt, shieldSecret);
    const evidenceRef = randomRef('EDGE');
    const event = {
      actor: observation.event.identity.actor,
      actorNamespace: 'network',
      evidenceRef,
      kind: 'edge_attempt',
      observedAt,
      schema: INCIDENT_SCHEMA,
      service,
    };
    const evidenceReceipt = createEvidenceReceipt({
      id: 'INC_' + evidenceRef,
      findingId: 'FIND_' + evidenceRef,
      check: 'shield_event',
      state: signedSource.state,
      observedAt,
      identity,
      summary: 'Authenticated Shield attempt observed by the source Worker.',
      evidenceRefs: signedSource.evidenceRefs,
    });
    return publish(event, evidenceReceipt);
  }

  async function onPrivilegeChange({ principalId, operation, committed } = {}) {
    if (committed !== true || !['policy_saved', 'key_rotated'].includes(operation)
      || typeof principalId !== 'string' || !principalId.trim() || principalId.length > 128) {
      throw new TypeError('INCIDENT_UNTRUSTED_PRIVILEGE_SOURCE');
    }
    const observedAt = clock();
    const key = await signer(signingSecret);
    const actor = hex(await crypto.subtle.sign('HMAC', key, encoder.encode('principal:' + service + ':' + principalId)));
    const evidenceRef = randomRef('PRIV');
    const event = {
      actor,
      actorNamespace: 'principal',
      evidenceRef,
      kind: 'privilege_change',
      observedAt,
      schema: INCIDENT_SCHEMA,
      service,
    };
    const evidenceReceipt = createEvidenceReceipt({
      id: 'INC_' + evidenceRef,
      findingId: 'FIND_' + evidenceRef,
      check: 'server_privilege_change',
      state: 'inferred',
      observedAt,
      identity,
      summary: 'Server reported a completed account boundary change; external confirmation pending.',
      evidenceRefs: ['incident:' + evidenceRef],
    });
    return publish(event, evidenceReceipt);
  }
  return Object.freeze({ onShieldAttempt, onPrivilegeChange });
}
