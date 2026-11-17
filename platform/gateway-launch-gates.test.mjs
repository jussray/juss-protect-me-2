// Launch gates from the Medusa v1.2 review of the deployed gateway (G1, G2, G3, G5, G7).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createGateway, findUserByKey } from './gateway.mjs';
import { accountToken, readAccountToken, createPayments } from './payments.mjs';
import { createStore, addUser } from './store.mjs';

const env = { SESSION_SECRET: 'test-secret-not-real' };
const enc = new TextEncoder();
const sha256Hex = async (s) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)))].map((b) => b.toString(16).padStart(2, '0')).join('');

let n = 0;
async function member(store, { indexed = true, policy = {} } = {}) {
  const id = `m${++n}`;
  const key = `jp2_${'a'.repeat(31)}${n}`;
  const user = { id, email: `${id}@example.invalid`, plan: 'two', entitlement: 'active', policy, apiKeyHash: await sha256Hex(key), apiKeyPrefix: key.slice(0, 8) };
  await addUser(store, user);
  if (indexed) await store.put(`keyhash:${user.apiKeyHash}`, id);
  return { user, key };
}
const check = (gw, key, body, e = env) => gw.fetch(new Request('https://x/gateway/check', {
  method: 'POST', headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body),
}), e);
const actions = (gw, token) => gw.fetch(new Request(`https://x/account/actions?token=${encodeURIComponent(token)}`), env);

// G5: no unauthenticated full-member scan.
test('G5: a key without a keyhash index entry is not found by scanning every member', async () => {
  const store = createStore();
  const { key } = await member(store, { indexed: false });
  assert.equal(await findUserByKey(store, key), null);
});
test('G5: an indexed key still resolves', async () => {
  const store = createStore();
  const { user, key } = await member(store);
  assert.equal((await findUserByKey(store, key)).id, user.id);
});

// G2: the policed agent cannot forge or bloat its own audit trail.
test('G2: a tool name with a newline is blocked as invalid_tool and cannot forge log lines', async () => {
  const store = createStore();
  const { user, key } = await member(store);
  const forged = 'x\n2026-01-01T00:00:00.000Z — read_file: ALLOW';
  const res = await (await check(createGateway({ store }), key, { tool: forged })).json();
  assert.equal(res.decision, 'block');
  assert.ok(res.reasons.includes('invalid_tool'), JSON.stringify(res.reasons));
  const text = await (await actions(createGateway({ store }), await accountToken(env, user))).text();
  assert.doesNotMatch(text, /read_file: ALLOW/);
  assert.equal(text.trim().split('\n').length, 1);
});
test('G2: an over-long tool name is blocked as invalid_tool', async () => {
  const store = createStore();
  const { key } = await member(store);
  const res = await (await check(createGateway({ store }), key, { tool: 'a'.repeat(129) })).json();
  assert.ok(res.reasons.includes('invalid_tool'));
});

// G3: concurrent checks are all recorded.
// KV is remote: reads and writes yield. Model that so read-modify-write races are real.
function slowStore() {
  const inner = createStore();
  const pause = () => new Promise((r) => setTimeout(r, Math.floor(Math.random() * 4)));
  const wrapped = {};
  for (const k of Object.keys(inner)) wrapped[k] = typeof inner[k] === 'function' ? async (...a) => { await pause(); return inner[k](...a); } : inner[k];
  return wrapped;
}
test('G3: twenty concurrent checks all appear in the action log', async () => {
  const store = slowStore();
  const { user, key } = await member(store);
  const gw = createGateway({ store });
  await Promise.all(Array.from({ length: 20 }, (_, i) => check(gw, key, { tool: `t${i}` })));
  const text = await (await actions(gw, await accountToken(env, user))).text();
  assert.equal(text.trim().split('\n').length, 20, text);
});

// G1: account links expire and can be revoked.
test('G1: a fresh account link resolves to its member', async () => {
  const store = createStore();
  const { user } = await member(store);
  assert.equal(await readAccountToken(env, await accountToken(env, user), store), user.id);
});
test('G1: an expired account link is refused', async () => {
  const store = createStore();
  const { user } = await member(store);
  const token = await accountToken(env, user, Date.now() - 8 * 24 * 3600 * 1000);
  assert.equal(await readAccountToken(env, token, store), null);
});
test('G1: a tampered account link is refused', async () => {
  const store = createStore();
  const { user } = await member(store);
  const token = await accountToken(env, user);
  const parts = token.split('.');
  parts[1] = String(Number(parts[1]) + 1e9);
  assert.equal(await readAccountToken(env, parts.join('.'), store), null);
});
test('G1: the old never-expiring link format is refused', async () => {
  const store = createStore();
  const { user } = await member(store);
  const key = await crypto.subtle.importKey('raw', enc.encode(env.SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = [...new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(`account:${user.id}`)))].map((b) => b.toString(16).padStart(2, '0')).join('');
  assert.equal(await readAccountToken(env, `${user.id}.${sig}`, store), null);
});
test('G1: rotating the gateway key signs out every earlier account link', async () => {
  const store = createStore();
  const { user } = await member(store);
  const oldToken = await accountToken(env, user);
  const form = new FormData();
  form.set('token', oldToken);
  const res = await createPayments({ store }).fetch(new Request('https://x/account/rotate', { method: 'POST', body: form }), env);
  assert.equal(res.status, 200);
  assert.equal(await readAccountToken(env, oldToken, store), null);
  const back = (await res.text()).match(/\/account\?token=([^"]+)"/);
  assert.ok(back, 'rotate page links back with a fresh account link');
  assert.equal(await readAccountToken(env, decodeURIComponent(back[1]), store), user.id);
});
test('G1: a stolen link cannot change boundaries once the member has rotated', async () => {
  const store = createStore();
  const { user } = await member(store, { policy: { tools: ['read_file'] } });
  const stolen = await accountToken(env, user);
  const rot = new FormData(); rot.set('token', stolen);
  await createPayments({ store }).fetch(new Request('https://x/account/rotate', { method: 'POST', body: rot }), env);
  const form = new FormData(); form.set('token', stolen); form.set('mode', 'open');
  const res = await createPayments({ store }).fetch(new Request('https://x/account/policy', { method: 'POST', body: form }), env);
  assert.equal(res.status, 403);
  assert.deepEqual((await store.get(`user:${user.id}`)).policy, { tools: ['read_file'] });
});

// G7: the per-member limit uses the shared rate-limit binding when present.
test('G7: the member limiter binding is keyed by member and blocks when exhausted', async () => {
  const store = createStore();
  const { user, key } = await member(store);
  const seen = [];
  const limited = { ...env, GATEWAY_MEMBER_LIMITER: { limit: async ({ key: k }) => { seen.push(k); return { success: false }; } } };
  const res = await (await check(createGateway({ store }), key, { tool: 'read_file' }, limited)).json();
  assert.deepEqual(seen, [`member:${user.id}`]);
  assert.ok(res.reasons.includes('rate_limit'));
});
test('G7: a failing limiter binding fails closed', async () => {
  const store = createStore();
  const { key } = await member(store);
  const broken = { ...env, GATEWAY_MEMBER_LIMITER: { limit: async () => { throw new Error('down'); } } };
  const res = await (await check(createGateway({ store }), key, { tool: 'read_file' }, broken)).json();
  assert.equal(res.decision, 'block');
  assert.ok(res.reasons.includes('rate_limit_unavailable'));
});
