import test from 'node:test';
import assert from 'node:assert/strict';
import { classify, observationForTelemetry } from './shield.mjs';
import { createIncidentSignalBridge } from './incident-signal-bridge.mjs';
import { createIncidentEvidenceConsumer } from './incident-evidence-consumer.mjs';

const clock = () => '2026-11-07T06:00:00.000Z';
const shieldSecret = 'shield-consumer-test-secret-123';
const signingSecret = 'incident-consumer-test-secret-123';
const identity = { source: { repository: 'jussray/juss-protect-me-2', branch: 'main', commitSha: 'a'.repeat(40) } };
function durableMemory() {
  const values = new Map();
  return {
    values,
    async transaction(callback) {
      const staging = new Map(values);
      const tx = { get: async (k) => structuredClone(staging.get(k) ?? null),
        put: async (k, value) => staging.set(k, structuredClone(value)) };
      const result = await callback(tx);
      values.clear();
      for (const [k, v] of staging) values.set(k, v);
      return result;
    },
  };
}
function fixture(service = 'juss-protect-me-2', storage = durableMemory()) {
  const sent = [];
  const bridge = createIncidentSignalBridge({ service, identity, shieldSecret, signingSecret,
    clock, sink: { send: async (message) => sent.push(message) } });
  const consumer = createIncidentEvidenceConsumer({ service, signingSecret, storage, clock });
  return { bridge, consumer, sent, storage };
}
async function shieldAttempt(service) {
  const source = await classify({ method: 'GET', url: 'https://example.test/.env', userAgent: 'curl',
    sourceIp: '203.0.113.42' }, { service }, shieldSecret);
  return { ...await observationForTelemetry(source, shieldSecret),
    transportAuthority: { level: 'evidence_only', canAuthorize: false } };
}

test('an accepted signed event is stored, while redelivery across calls is not counted twice', async () => {
  const { bridge, consumer, sent, storage } = fixture();
  await bridge.onShieldAttempt(await shieldAttempt('juss-protect-me-2'));
  const first = await consumer.accept(sent[0]);
  assert.equal(first.state, 'NO_CORRELATION');
  assert.equal(first.stored, true);
  const replay = await consumer.accept(sent[0]);
  assert.deepEqual(replay, { state: 'DUPLICATE', stored: false, canAuthorize: false });
  assert.equal(storage.values.get('incident-journal:juss-protect-me-2').length, 1);
});

test('serially delivered signed source events correlate across separate transaction calls', async () => {
  const { bridge, consumer, sent } = fixture();
  for (let i = 0; i < 3; i++) {
    await bridge.onShieldAttempt(await shieldAttempt('juss-protect-me-2'));
    assert.equal((await consumer.accept(sent[sent.length - 1])).canAuthorize, false);
  }
  await bridge.onPrivilegeChange({ principalId: 'private-member', operation: 'key_rotated', committed: true });
  const result = await consumer.accept(sent[sent.length - 1]);
  assert.equal(result.state, 'REVIEW');
  assert.equal(result.report.findings.length, 1);
  assert.equal(result.report.findings[0].action, 'manual_review');
  assert.equal(result.report.findings[0].attribution, 'unconfirmed');
});

test('unsigned or modified events cannot poison persistent journal', async () => {
  const { bridge, consumer, sent, storage } = fixture();
  await bridge.onShieldAttempt(await shieldAttempt('juss-protect-me-2'));
  const original = sent[0];
  for (const invalid of [
    { ...original, observation: { ...original.observation, receipt: 'f'.repeat(64) } },
    { ...original, observation: { ...original.observation, event: { ...original.observation.event, service: 'different-service' } } },
    { ...original, observation: { ...original.observation, event: { ...original.observation.event, evidenceRef: 'EDGE_FORGED' } } },
    { ...original, authority: { level: 'admin', canAuthorize: true } },
  ]) await assert.rejects(consumer.accept(invalid), /INCIDENT_UNTRUSTED_ENVELOPE|INCIDENT_UNTRUSTED_EVIDENCE/);
  assert.equal(storage.values.size, 0);
});

test('different services cannot cross-populate evidence journals', async () => {
  const storage = durableMemory();
  const first = fixture('juss-protect-me-2', storage);
  const second = fixture('other-service', storage);
  await first.bridge.onShieldAttempt(await shieldAttempt('juss-protect-me-2'));
  await assert.rejects(second.consumer.accept(first.sent[0]), /INCIDENT_UNTRUSTED_ENVELOPE/);
  await first.consumer.accept(first.sent[0]);
  assert.equal(storage.values.has('incident-journal:other-service'), false);
});

test('missing durable transaction support, corrupted storage and full bounded windows fail closed', async () => {
  assert.throws(() => createIncidentEvidenceConsumer({ service: 'juss-protect-me-2', signingSecret,
    storage: { get() {}, put() {} }, clock }), /INCIDENT_TRANSACTIONAL_STORAGE_REQUIRED/);
  const { bridge, consumer, sent, storage } = fixture();
  await bridge.onShieldAttempt(await shieldAttempt('juss-protect-me-2'));
  storage.values.set('incident-journal:juss-protect-me-2', { corrupted: true });
  await assert.rejects(consumer.accept(sent[0]), /INCIDENT_JOURNAL_CORRUPTED/);
  storage.values.set('incident-journal:juss-protect-me-2',
    Array.from({ length: 256 }, (_, i) => ({ event: { observedAt: clock(), evidenceRef: 'EDGE_FULL_' + i } })));
  await assert.rejects(consumer.accept(sent[0]), /INCIDENT_WINDOW_FULL/);
});
