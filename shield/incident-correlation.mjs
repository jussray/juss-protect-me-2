// Passive incident correlation for authorized, server-signed security evidence.
// No network calls, enforcement, production collector, or authorization decisions.
// Service-wide temporal coincidence is not proof of shared actor or compromise.

export const INCIDENT_SCHEMA = 'protect-me/incident-event@v1';
export const CORRELATION_SCHEMA = 'protect-me/incident-correlation@v1';
const KINDS = new Set(['edge_attempt', 'privilege_change', 'high_volume_data_access']);
const EVENT_FIELDS = ['actor', 'actorNamespace', 'evidenceRef', 'kind', 'observedAt', 'schema', 'service'];
const MAX_EVENTS = 256;
const MAX_FINDINGS = 32;
const MAX_AGE_MS = 10 * 60_000;
const MAX_FUTURE_MS = 5_000;
const OPAQUE_ACTOR = /^[a-f0-9]{64}$/;
const OPAQUE_REF = /^[A-Z][A-Z0-9_-]{2,63}$/;
const SERVICE = /^[a-z][a-z0-9-]{2,63}$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const encoder = new TextEncoder();

function safeTime(value) {
  if (typeof value !== 'string' || !RFC3339_UTC.test(value)) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value ? time : null;
}

function validEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) return false;
  if (Object.keys(event).sort().join('|') !== EVENT_FIELDS.join('|')) return false;
  if (event.schema !== INCIDENT_SCHEMA || !KINDS.has(event.kind)) return false;
  if (!SERVICE.test(event.service) || !OPAQUE_REF.test(event.evidenceRef)) return false;
  if (!OPAQUE_ACTOR.test(event.actor) || safeTime(event.observedAt) === null) return false;
  return event.kind === 'edge_attempt' ? event.actorNamespace === 'network'
    : event.actorNamespace === 'principal';
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

function hexBytes(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) return null;
  return Uint8Array.from(value.match(/../g), (part) => Number.parseInt(part, 16));
}

/**
 * Source-only assessment. The caller must supply independently authenticated,
 * server-produced observations and a server-held signing secret. An invalid
 * observation rejects the entire batch rather than silently becoming clean.
 *
 * @param {{observations: Array<{event: object, receipt: string, receiptKind: string}>,
 *   now: string, signingSecret: string, windowMs?: number, burstThreshold?: number}} input
 */
export async function correlateSecurityEvents({
  observations, now, signingSecret, windowMs = 60_000, burstThreshold = 3,
} = {}) {
  if (!Array.isArray(observations) || observations.length > MAX_EVENTS) {
    throw new TypeError('INCIDENT_INVALID_BATCH');
  }
  if (typeof signingSecret !== 'string' || signingSecret.length < 16) {
    throw new TypeError('INCIDENT_SIGNING_KEY_UNAVAILABLE');
  }
  const nowMs = safeTime(now);
  if (nowMs === null || !Number.isInteger(windowMs) || windowMs < 1000 || windowMs > 300_000
    || !Number.isInteger(burstThreshold) || burstThreshold < 3 || burstThreshold > 20) {
    throw new TypeError('INCIDENT_INVALID_SETTINGS');
  }
  const key = await crypto.subtle.importKey('raw', encoder.encode(signingSecret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const events = [];
  const seen = new Map();
  let ignoredStale = 0;
  let duplicates = 0;
  for (const observation of observations) {
    const event = observation?.event;
    if (!validEvent(event) || observation.receiptKind !== 'hmac-sha256') {
      throw new TypeError('INCIDENT_UNTRUSTED_EVIDENCE');
    }
    const signature = hexBytes(observation.receipt);
    if (!signature || !(await crypto.subtle.verify('HMAC', key, signature,
      encoder.encode(JSON.stringify(stable(event)))))) {
      throw new TypeError('INCIDENT_UNTRUSTED_EVIDENCE');
    }
    const previous = seen.get(event.evidenceRef);
    if (previous) {
      if (previous !== observation.receipt) throw new TypeError('INCIDENT_CONFLICTING_EVIDENCE');
      duplicates += 1;
      continue;
    }
    seen.set(event.evidenceRef, observation.receipt);
    const observedMs = safeTime(event.observedAt);
    if (observedMs > nowMs + MAX_FUTURE_MS) throw new TypeError('INCIDENT_FUTURE_EVIDENCE');
    if (observedMs < nowMs - MAX_AGE_MS) { ignoredStale += 1; continue; }
    events.push({ ...event, observedMs });
  }
  events.sort((a, b) => a.observedMs - b.observedMs || a.evidenceRef.localeCompare(b.evidenceRef));
  const findings = [];
  for (const sensitive of events) {
    if (sensitive.kind === 'edge_attempt') continue;
    const matching = events.filter((candidate) => candidate.kind === 'edge_attempt'
      && candidate.service === sensitive.service
      && candidate.observedMs >= sensitive.observedMs - windowMs
      && candidate.observedMs <= sensitive.observedMs);
    const groups = new Map();
    for (const event of matching) {
      const group = groups.get(event.actor) ?? [];
      group.push(event);
      groups.set(event.actor, group);
    }
    const burst = [...groups.values()].find((group) => group.length >= burstThreshold);
    if (!burst) continue;
    findings.push(Object.freeze({
      kind: 'service_temporal_coincidence',
      service: sensitive.service,
      coincidentSignal: sensitive.kind,
      edgeAttemptCount: burst.length,
      evidenceRefs: Object.freeze([
        ...burst.slice(-burstThreshold).map((event) => event.evidenceRef),
        sensitive.evidenceRef,
      ]),
      attribution: 'unconfirmed',
      action: 'manual_review',
      authority: Object.freeze({ level: 'evidence_only', canAuthorize: false }),
    }));
    if (findings.length >= MAX_FINDINGS) break;
  }
  return Object.freeze({
    schema: CORRELATION_SCHEMA,
    state: findings.length ? 'REVIEW' : events.length ? 'NO_CORRELATION' : 'UNKNOWN',
    inspected: events.length,
    ignoredStale,
    duplicates,
    findings: Object.freeze(findings),
    canAuthorize: false,
  });
}
