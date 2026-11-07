import test from 'node:test';
import assert from 'node:assert/strict';
import { correlateSecurityEvents, INCIDENT_SCHEMA } from './incident-correlation.mjs';

const secret = 'test-only-secret-never-deploy';
const actor = 'a'.repeat(64);
const principal = 'b'.repeat(64);
const start = Date.parse('2026-11-07T06:00:00.000Z');
const iso = (offset) => new Date(start + offset).toISOString();
const base = { schema: INCIDENT_SCHEMA, service: 'protect-me-2' };
const edge = (offset, evidenceRef, changes = {}) => ({ ...base, kind: 'edge_attempt', actor,
  actorNamespace: 'network', observedAt: iso(offset), evidenceRef, ...changes });
const sensitive = (kind, offset, evidenceRef, changes = {}) => ({ ...base, kind, actor: principal,
  actorNamespace: 'principal', observedAt: iso(offset), evidenceRef, ...changes });
const sorted = (value) => Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]]));
async function seal(event) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const buf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(JSON.stringify(sorted(event))));
  return { event, receipt: [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join(''), receiptKind: 'hmac-sha256' };
}
async function run(events, options = {}) {
  return correlateSecurityEvents({ observations: await Promise.all(events.map(seal)), now: iso(60_000), signingSecret: secret, ...options });
}
const burst = [edge(0, 'EDGE001'), edge(1000, 'EDGE002'), edge(2000, 'EDGE003')];

test('correlates a signed request burst with a privileged action as review only', async () => {
  const result = await run([...burst, sensitive('privilege_change', 3000, 'IAM001')]);
  assert.equal(result.state, 'REVIEW');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].action, 'manual_review');
  assert.equal(result.findings[0].attribution, 'unconfirmed');
  assert.deepEqual(result.findings[0].evidenceRefs, ['EDGE001', 'EDGE002', 'EDGE003', 'IAM001']);
  assert.deepEqual(result.findings[0].authority, { level: 'evidence_only', canAuthorize: false });
  assert.ok(!JSON.stringify(result).includes(actor));
});

test('also flags an anomalous data-access signal but does not infer compromise', async () => {
  const result = await run([...burst, sensitive('high_volume_data_access', 3000, 'DATA001')]);
  assert.equal(result.findings[0].coincidentSignal, 'high_volume_data_access');
  assert.equal(result.canAuthorize, false);
});

test('does not correlate unrelated services, spaced events, or distinct network actors', async () => {
  const cases = [
    [...burst, sensitive('privilege_change', 3000, 'IAM001', { service: 'other-service' })],
    [...burst, sensitive('privilege_change', 65_000, 'IAM001')],
    [edge(0, 'EDGE001'), edge(1000, 'EDGE002', { actor: 'c'.repeat(64) }),
      edge(2000, 'EDGE003', { actor: 'd'.repeat(64) }), sensitive('privilege_change', 3000, 'IAM001')],
  ];
  for (const input of cases) assert.equal((await run(input)).state, 'NO_CORRELATION');
});

test('deduplicates identical replay and blocks conflicting evidence references', async () => {
  const entries = await Promise.all([...burst, sensitive('privilege_change', 3000, 'IAM001')].map(seal));
  let result = await correlateSecurityEvents({ observations: [...entries, entries[0]], now: iso(60_000), signingSecret: secret });
  assert.equal(result.duplicates, 1);
  assert.equal(result.findings.length, 1);
  const other = await seal(edge(3500, 'EDGE001'));
  await assert.rejects(correlateSecurityEvents({ observations: [...entries, other], now: iso(60_000), signingSecret: secret }), /INCIDENT_CONFLICTING_EVIDENCE/);
});

test('rejects forged, unsigned, and tampered evidence without a clean fallback', async () => {
  const observation = await seal(edge(0, 'EDGE001'));
  for (const invalid of [
    { ...observation, receiptKind: 'sha256-unauthenticated' },
    { ...observation, receipt: '0'.repeat(64) },
    { ...observation, event: { ...observation.event, kind: 'privilege_change' } },
  ]) await assert.rejects(correlateSecurityEvents({ observations: [invalid], now: iso(60_000), signingSecret: secret }), /INCIDENT_UNTRUSTED_EVIDENCE/);
});

test('requires opaque IDs, time proof, and strict schema; ignores old signed events', async () => {
  for (const invalid of [
    edge(0, 'EDGE001', { email: 'private@example.test' }),
    edge(0, 'EDGE001', { actor: '192.0.2.5' }),
    edge(0, 'PRIVATE.EMAIL@example.test'),
    edge(0, 'EDGE001', { actorNamespace: 'principal' }),
  ]) await assert.rejects(correlateSecurityEvents({ observations: [await seal(invalid)], now: iso(60_000), signingSecret: secret }), /INCIDENT_UNTRUSTED_EVIDENCE/);
  const stale = await run([edge(-700_000, 'EDGE001'), sensitive('privilege_change', 3000, 'IAM001')]);
  assert.equal(stale.state, 'NO_CORRELATION');
  assert.equal(stale.ignoredStale, 1);
  await assert.rejects(run([edge(70_000, 'EDGE001')]), /INCIDENT_FUTURE_EVIDENCE/);
});

test('enforces bounded processing and deterministic order', async () => {
  await assert.rejects(run(Array.from({ length: 257 }, (_, i) => edge(i, 'E' + String(i).padStart(5, '0')))), /INCIDENT_INVALID_BATCH/);
  await assert.rejects(run([], { signingSecret: '' }), /INCIDENT_SIGNING_KEY_UNAVAILABLE/);
  await assert.rejects(run([], { burstThreshold: 1 }), /INCIDENT_INVALID_SETTINGS/);
  const values = [...burst, sensitive('privilege_change', 3000, 'IAM001')];
  assert.deepEqual(await run(values), await run([...values].reverse()));
});

test('empty verified-input set is UNKNOWN, never a clean bill of health', async () => {
  const result = await run([]);
  assert.equal(result.state, 'UNKNOWN');
  assert.equal(result.inspected, 0);
  assert.equal(result.canAuthorize, false);
});
