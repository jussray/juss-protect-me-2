import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import { createGateway, evaluateCheck, findUserByKey } from './gateway.mjs';
import { addUser, createStore } from './store.mjs';

const hash = (value) => createHash('sha256').update(value).digest('hex');
const member = (id, extra = {}) => ({
  id, plan: 'two', entitlement: 'active', policy: {},
  apiKeyHash: hash('jp2_' + id), ...extra,
});

test('Model Two active membership can use a valid ordinary tool', async () => {
  const result = await evaluateCheck(createStore(), member('good-member'), { tool: 'calendar.read' });
  assert.equal(result.decision, 'allow');
  assert.deepEqual(result.reasons, []);
});

test('missing, malformed or oversized tool names deny rather than allow', async () => {
  for (const [index, tool] of [undefined, '', '   ', 'read tool', 'a'.repeat(65)].entries()) {
    const result = await evaluateCheck(createStore(), member('bad-tool-' + index), { tool });
    assert.equal(result.decision, 'block');
    assert.ok(result.reasons.includes('invalid_tool'));
  }
});

test('a Model One active entitlement cannot authorize Model Two tools', async () => {
  const result = await evaluateCheck(createStore(), member('model-one', { plan: 'one' }), { tool: 'calendar.read' });
  assert.equal(result.decision, 'block');
  assert.ok(result.reasons.includes('wrong_product'));
});

test('inactive Model Two membership denies tools', async () => {
  const result = await evaluateCheck(createStore(), member('inactive', { entitlement: 'inactive' }), { tool: 'calendar.read' });
  assert.equal(result.decision, 'block');
  assert.ok(result.reasons.includes('membership_inactive'));
});

test('hard deny list cannot be bypassed through capitalization', async () => {
  for (const [index, tool] of ['SHELL_EXEC', 'Admin.delete', 'PAYMENT_SEND'].entries()) {
    const result = await evaluateCheck(createStore(), member('denied-' + index), { tool });
    assert.equal(result.decision, 'block');
    assert.ok(result.reasons.includes('tool_denied_by_default'));
  }
});

test('member allowlist and blocklist remain enforced', async () => {
  const result = await evaluateCheck(
    createStore(),
    member('member-policy', { policy: { tools: ['calendar.read'], deniedTools: ['Calendar.Read'] } }),
    { tool: 'calendar.read' },
  );
  assert.equal(result.decision, 'block');
  assert.ok(result.reasons.includes('tool_denied_by_member'));
});

test('stale keyhash indexes never authorize the wrong member or an old key', async () => {
  const store = createStore();
  const staleKey = 'jp2_stale_key_value';
  const user = member('stale-member');
  await addUser(store, user);
  await store.put('keyhash:' + hash(staleKey), user.id);
  assert.equal(await findUserByKey(store, staleKey), null);
});

test('a Model One key cannot be used against the Model Two gateway', async () => {
  const store = createStore();
  const key = 'jp2_model_one_mistake';
  const user = member('one-key', { plan: 'one', apiKeyHash: hash(key) });
  await addUser(store, user);
  await store.put('keyhash:' + hash(key), user.id);
  assert.equal(await findUserByKey(store, key), null);
});

test('real gateway POST denies unauthenticated calls, including with a tool', async () => {
  const gateway = createGateway({ store: createStore() });
  const result = await gateway.fetch(new Request('https://protect2.example/gateway/check', {
    method: 'POST',
    headers: { Authorization: 'Bearer jp2_invalid', 'Content-Type': 'application/json' },
    body: JSON.stringify({ tool: 'calendar.read' }),
  }), {});
  assert.equal(result.status, 401);
  const data = await result.json();
  assert.equal(data.decision, 'block');
  assert.deepEqual(data.reasons, ['invalid_key']);
});
