import test from 'node:test';
import assert from 'node:assert/strict';
import { classify, observationForTelemetry } from './shield.mjs';
import { correlateSecurityEvents } from './incident-correlation.mjs';
import { createIncidentSignalBridge } from './incident-signal-bridge.mjs';

const shieldSecret = 'shield-only-test-secret-1234';
const signingSecret = 'incident-only-test-secret-1234';
const identity = { source: { repository: 'jussray/juss-protect-me-2', branch: 'security/sauce-guard-cyber-v1', commitSha: 'a'.repeat(40) } };
const now = '2026-11-07T06:00:00.000Z';
const setup = (service = 'juss-protect-me-2') => {
  const messages = [];
  const bridge = createIncidentSignalBridge({ service, identity, shieldSecret, signingSecret,
    clock: () => now, sink: { send: async (message) => { messages.push(message); } } });
  return { bridge, messages };
};
const source = async (service = 'juss-protect-me-2') => {
  const observed = await classify({ method: 'GET', url: 'https://protect.example/.git/config',
    userAgent: 'curl', sourceIp: '203.0.113.22' }, { service }, shieldSecret);
  return Object.freeze({ ...await observationForTelemetry(observed, shieldSecret),
    transportAuthority: Object.freeze({ level: 'evidence_only', canAuthorize: false }) });
};

test('real Shield HMAC yields a redacted evidence receipt and signed correlation input', async () => {
  const { bridge, messages } = setup();
  const observation = await source();
  const queued = await bridge.onShieldAttempt(observation);
  assert.equal(queued.queued, true);
  assert.equal(queued.canAuthorize, false);
  assert.equal(messages.length, 1);
  const payload = messages[0];
  assert.equal(payload.evidenceReceipt.state, 'verified');
  assert.equal(payload.authority.canAuthorize, false);
  const printed = JSON.stringify(payload);
  assert.ok(!printed.includes('203.0.113.22'));
  assert.ok(!printed.includes('/.git/config'));
  assert.ok(!printed.includes('curl'));
  assert.equal((await correlateSecurityEvents({ observations: [payload.observation], now, signingSecret })).state, 'NO_CORRELATION');
});

test('three trusted requests plus a committed server policy change produce review-only coincidence', async () => {
  const { bridge, messages } = setup();
  for (let i = 0; i < 3; i++) await bridge.onShieldAttempt(await source());
  await bridge.onPrivilegeChange({ principalId: 'private-member-id', operation: 'policy_saved', committed: true });
  assert.equal(messages.length, 4);
  const result = await correlateSecurityEvents({ observations: messages.map((p) => p.observation), now, signingSecret });
  assert.equal(result.state, 'REVIEW');
  assert.equal(result.findings[0].attribution, 'unconfirmed');
  assert.equal(result.findings[0].authority.canAuthorize, false);
  assert.equal(messages[3].evidenceReceipt.state, 'inferred');
  assert.ok(!JSON.stringify(messages).includes('private-member-id'));
  assert.equal(new Set(messages.map((x) => x.observation.event.evidenceRef)).size, 4);
});

test('rejects forged Shield receipts, another service, missing actor and wrong signer', async () => {
  const { bridge, messages } = setup();
  const original = await source();
  const bad = [
    { ...original, receipt: 'f'.repeat(64) },
    { ...original, event: { ...original.event, service: 'another-service' } },
    { ...original, event: { ...original.event, identity: { ...original.event.identity, actor: null } } },
    { ...original, receiptKind: 'sha256-unauthenticated' },
  ];
  for (const o of bad) await assert.rejects(bridge.onShieldAttempt(o), /INCIDENT_UNTRUSTED_SHIELD_SOURCE|SIGNATURE_UNVERIFIED/);
  assert.equal(messages.length, 0);
});

test('rejects uncommitted or malformed privileged actions and missing delivery authority', async () => {
  const { bridge, messages } = setup();
  for (const event of [
    { principalId: 'member', operation: 'policy_saved', committed: false },
    { principalId: 'member', operation: 'invented', committed: true },
    { principalId: '', operation: 'key_rotated', committed: true },
  ]) await assert.rejects(bridge.onPrivilegeChange(event), /INCIDENT_UNTRUSTED_PRIVILEGE_SOURCE/);
  assert.equal(messages.length, 0);
  assert.throws(() => createIncidentSignalBridge({ service: 'juss-protect-me-2', identity, shieldSecret, signingSecret }), /INCIDENT_DURABLE_SINK_REQUIRED/);
  assert.throws(() => createIncidentSignalBridge({ service: 'juss-protect-me-2', identity, shieldSecret, signingSecret: shieldSecret, sink: { send() {} } }), /INCIDENT_KEYS_MUST_BE_SEPARATE/);
});

test('source is service-scoped; repeated message delivery is deduplicated in a batch', async () => {
  const { bridge, messages } = setup();
  await assert.rejects(bridge.onShieldAttempt(await source('other-service')), /INCIDENT_UNTRUSTED_SHIELD_SOURCE/);
  await bridge.onShieldAttempt(await source());
  const result = await correlateSecurityEvents({ observations: [messages[0].observation, messages[0].observation], now, signingSecret });
  assert.equal(result.duplicates, 1);
  assert.equal(result.inspected, 1);
});
