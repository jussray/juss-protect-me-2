// Passive, transactional incident signal consumer.
// Require a strongly consistent, service-scoped transaction implementation
// (e.g. Cloudflare Durable Object storage). Cloudflare KV is NOT sufficient.
// Not wired to live queues, endpoints, alerts, or automatic containment.
import { correlateSecurityEvents } from './incident-correlation.mjs';

const MAX_JOURNAL = 256;
const MAX_AGE_MS = 10 * 60_000;
const SERVICE_RE = /^[a-z][a-z0-9-]{2,63}$/;

export function createIncidentEvidenceConsumer({
  service, signingSecret, storage, clock = () => new Date().toISOString(),
} = {}) {
  if (!SERVICE_RE.test(service ?? '')) throw new TypeError('INCIDENT_INVALID_SERVICE');
  if (typeof signingSecret !== 'string' || signingSecret.length < 16) {
    throw new TypeError('INCIDENT_SIGNING_SECRET_UNAVAILABLE');
  }
  if (!storage || typeof storage.transaction !== 'function' || typeof clock !== 'function') {
    throw new TypeError('INCIDENT_TRANSACTIONAL_STORAGE_REQUIRED');
  }

  async function accept(envelope) {
    if (envelope?.schema !== 'protect-me/incident-signal-envelope@v1'
      || envelope.authority?.level !== 'evidence_only'
      || envelope.authority?.canAuthorize !== false
      || envelope.observation?.event?.service !== service) {
      throw new TypeError('INCIDENT_UNTRUSTED_ENVELOPE');
    }

    const observedNow = clock();
    // Verify the signed event, source fields, future drift and staleness BEFORE
    // touching storage. The unsigned evidenceReceipt is not consumer authority.
    const verified = await correlateSecurityEvents({
      observations: [envelope.observation], now: observedNow, signingSecret,
    });
    if (verified.inspected !== 1 || verified.ignoredStale) {
      throw new TypeError('INCIDENT_STALE_EVIDENCE');
    }

    const key = 'incident-journal:' + service;
    return storage.transaction(async (transaction) => {
      const existing = await transaction.get(key);
      if (existing !== null && existing !== undefined && !Array.isArray(existing)) {
        throw new TypeError('INCIDENT_JOURNAL_CORRUPTED');
      }
      const cutoff = Date.parse(observedNow) - MAX_AGE_MS;
      const journal = (existing ?? []).filter((entry) => {
        const t = Date.parse(entry?.event?.observedAt);
        if (!Number.isFinite(t)) throw new TypeError('INCIDENT_JOURNAL_CORRUPTED');
        return t >= cutoff;
      });
      if (journal.length > MAX_JOURNAL) throw new TypeError('INCIDENT_JOURNAL_CORRUPTED');
      const event = envelope.observation.event;
      const replay = journal.find((entry) => entry?.event?.evidenceRef === event.evidenceRef);
      if (replay) {
        if (replay.receipt !== envelope.observation.receipt) {
          throw new TypeError('INCIDENT_CONFLICTING_EVIDENCE');
        }
        return Object.freeze({ state: 'DUPLICATE', stored: false, canAuthorize: false });
      }
      if (journal.length >= MAX_JOURNAL) throw new TypeError('INCIDENT_WINDOW_FULL');
      const next = [...journal, envelope.observation];
      // A poisoned journal can never be silently treated as clean.
      const report = await correlateSecurityEvents({ observations: next, now: observedNow, signingSecret });
      if (report.ignoredStale) throw new TypeError('INCIDENT_JOURNAL_STALE');
      await transaction.put(key, next);
      return Object.freeze({ state: report.state, stored: true, report, canAuthorize: false });
    });
  }
  return Object.freeze({ accept });
}
