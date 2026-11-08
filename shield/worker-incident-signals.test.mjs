import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker.mjs';
import { accountToken, createPayments } from '../platform/payments.mjs';
import { createStore, saveUser } from '../platform/store.mjs';
import { createIncidentSignalBridge } from './incident-signal-bridge.mjs';
import { correlateSecurityEvents } from './incident-correlation.mjs';

const keyA = 'shield-binding-test-secret-1234';
const keyB = 'incident-binding-test-secret-1234';
const identity = { source: { repository: 'jussray/juss-protect-me-2', branch: 'main', commitSha: 'a'.repeat(40) } };
const makeEnv = (sink) => ({
  ASSETS: { fetch: async () => new Response('static-ok', { status: 200 }) },
  SHIELD_SECRET: keyA,
  INCIDENT_SIGNALS_ENABLED: 'true',
  INCIDENT_SIGNING_SECRET: keyB,
  INCIDENT_SOURCE_BRANCH: 'main',
  INCIDENT_SOURCE_SHA: 'a'.repeat(40),
  INCIDENT_ENVIRONMENT: 'test',
  INCIDENT_BUILD_ID: 'synthetic-test-build',
  INCIDENT_EVIDENCE_QUEUE: sink,
});

test('existing Worker path is unchanged when signal mode is absent', async () => {
  const result = await worker.fetch(new Request('https://protect.example/'),
    { ASSETS: { fetch: async () => new Response('existing-app') } }, {});
  assert.equal(result.status, 200);
  assert.equal(await result.text(), 'existing-app');
});

test('flagged signal mode refuses missing server queue and evidence identity', async () => {
  const env = makeEnv({ send: async () => {} });
  await assert.rejects(worker.fetch(new Request('https://protect.example/'), { ...env, INCIDENT_EVIDENCE_QUEUE: null }, {}), /INCIDENT_DURABLE_SINK_REQUIRED/);
  await assert.rejects(worker.fetch(new Request('https://protect.example/'), { ...env, INCIDENT_SOURCE_SHA: 'short' }, {}), /commitSha/);
});

test('real Worker Shield event enters a signed, redacted evidence queue with no public route', async () => {
  const received = [];
  const tasks = [];
  const env = makeEnv({ send: async (evidence) => received.push(evidence) });
  const request = new Request('https://protect.example/.git/config?private=please', {
    headers: { 'user-agent': 'curl/8.0', 'cf-connecting-ip': '203.0.113.8' },
  });
  const response = await worker.fetch(request, env, { waitUntil: (p) => tasks.push(p) });
  assert.equal(response.status, 404);
  await Promise.all(tasks);
  assert.equal(received.length, 1);
  assert.equal(received[0].evidenceReceipt.state, 'verified');
  const serialized = JSON.stringify(received);
  for (const sensitive of ['203.0.113.8', 'curl/8.0', '.git/config', 'private=please']) assert.ok(!serialized.includes(sensitive));
  const result = await correlateSecurityEvents({ observations: [received[0].observation], now: new Date().toISOString(), signingSecret: keyB });
  assert.equal(result.state, 'NO_CORRELATION');
  assert.equal(result.canAuthorize, false);
});

test('only a successfully saved authenticated policy change emits principal evidence', async () => {
  const received = [];
  const sink = { send: async (item) => received.push(item) };
  const bridge = createIncidentSignalBridge({ service: 'juss-protect-me-2', identity,
    shieldSecret: keyA, signingSecret: keyB, sink });
  const store = createStore({});
  const user = { id: 'private-member-id', email: 'person@example.test', plan: 'two',
    entitlement: 'active', policy: {} };
  await saveUser(store, user);
  const env = { SESSION_SECRET: 'test-only-session-secret' };
  const token = await accountToken(env, user.id);
  const payments = createPayments({ store, onSecurityChange: bridge.onPrivilegeChange });
  const form = (value) => new Request('https://protect.example/account/policy',
    { method: 'POST', body: new URLSearchParams(value) });
  const denied = await payments.fetch(form({ token: 'bad', mode: 'allowlist' }), env);
  assert.equal(denied.status, 403);
  assert.equal(received.length, 0);
  const result = await payments.fetch(form({ token, mode: 'allowlist', allowedTools: 'search' }), env);
  assert.equal(result.status, 303);
  assert.equal((await store.get('user:private-member-id')).policy.tools[0], 'search');
  assert.equal(received.length, 1);
  assert.equal(received[0].observation.event.kind, 'privilege_change');
  assert.equal(received[0].evidenceReceipt.state, 'inferred');
  assert.ok(!JSON.stringify(received).includes(user.id));
  assert.ok(!JSON.stringify(received).includes(user.email));
});

test('non-authoritative delivery failures do not misreport a committed policy as failed', async () => {
  const store = createStore({});
  const user = { id: 'private-user', email: 'person@example.test', plan: 'two', entitlement: 'active', policy: {} };
  await saveUser(store, user);
  const env = { SESSION_SECRET: 'test-only-session-secret' };
  const token = await accountToken(env, user.id);
  const original = console.error;
  const errors = [];
  console.error = (code) => errors.push(code);
  try {
    const payments = createPayments({ store, onSecurityChange: async () => { throw new Error('must not leak'); } });
    const response = await payments.fetch(new Request('https://protect.example/account/policy',
      { method: 'POST', body: new URLSearchParams({ token, mode: 'allowlist', allowedTools: 'search' }) }), env);
    assert.equal(response.status, 303);
    assert.deepEqual(errors, ['INCIDENT_SIGNAL_DELIVERY_FAILED']);
    assert.equal((await store.get('user:private-user')).policy.tools[0], 'search');
  } finally {
    console.error = original;
  }
});
