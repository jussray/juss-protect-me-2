import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createStore } from './store.mjs';
import { createGateway, evaluateCheck } from './gateway.mjs';

let nextId = 0;
function activeUser(policy = {}) {
  return { id: `gateway-regression-${++nextId}`, entitlement: 'active', policy };
}

test('missing and malformed tool names fail closed', async () => {
  const user = activeUser();
  for (const tool of [undefined, null, '', ' ', 'admin/rotate', 'x'.repeat(65), 42]) {
    const result = await evaluateCheck(null, user, { tool, content: 'ordinary text' });
    assert.equal(result.decision, 'block', `tool: ${String(tool)}`);
    assert.ok(result.reasons.includes('invalid_tool'), `tool: ${String(tool)}`);
  }
});

test('built-in denied tools and admin namespace cannot be allowed by case changes', async () => {
  const user = activeUser({ tools: ['shell_exec', 'admin:grant', 'SHELL_EXEC', 'AdMiN.console'] });
  for (const tool of ['shell_exec', 'SHELL_EXEC', 'admin', 'admin:grant', 'AdMiN.console']) {
    const result = await evaluateCheck(null, user, { tool });
    assert.equal(result.decision, 'block', tool);
    assert.ok(result.reasons.includes('tool_denied_by_default'), tool);
  }
});

test('valid safe tools still honor allowlists, member denials, and entitlement', async () => {
  const open = activeUser();
  assert.equal((await evaluateCheck(null, open, { tool: 'search.read' })).decision, 'allow');
  assert.equal((await evaluateCheck(null, open, { tool: 'safe_tool-1' })).decision, 'allow');
  const allowlist = activeUser({ tools: ['search.read'] });
  assert.equal((await evaluateCheck(null, allowlist, { tool: 'search.read' })).decision, 'allow');
  assert.ok((await evaluateCheck(null, allowlist, { tool: 'other.read' })).reasons.includes('tool_not_allowed'));
  assert.ok((await evaluateCheck(null, activeUser({ tools: [] }), { tool: 'search.read' })).reasons.includes('tool_not_allowed'));
  assert.ok((await evaluateCheck(null, activeUser({ deniedTools: ['search.read'] }), { tool: 'search.read' })).reasons.includes('tool_denied_by_member'));
  const inactive = activeUser();
  inactive.entitlement = 'suspended';
  assert.equal((await evaluateCheck(null, inactive, { tool: 'search.read' })).decision, 'block');
});

test('gateway HTTP handler blocks missing tools, allows safe ones, and logs both decisions', async () => {
  const store = createStore();
  const user = activeUser();
  const key = 'jp2_synthetic_gateway_regression_key';
  const hash = createHash('sha256').update(key).digest('hex');
  await store.put(`keyhash:${hash}`, user.id);
  await store.put(`user:${user.id}`, user);
  const gateway = createGateway({ store });

  const send = (body, authorized = true) => gateway.fetch(new Request('https://protect.invalid/gateway/check', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(authorized ? { Authorization: `Bearer ${key}` } : {}),
    },
    body: JSON.stringify(body),
  }), {});

  const unauthorized = await send({ tool: 'search.read' }, false);
  assert.equal(unauthorized.status, 401);
  assert.equal((await unauthorized.json()).decision, 'block');

  const missing = await send({ content: 'ordinary text' });
  assert.equal(missing.status, 200); // Existing API contract returns a decision in JSON.
  const blocked = await missing.json();
  assert.equal(blocked.decision, 'block');
  assert.ok(blocked.reasons.includes('invalid_tool'));

  const valid = await send({ tool: 'search.read', content: 'ordinary text' });
  assert.equal(valid.status, 200);
  assert.equal((await valid.json()).decision, 'allow');

  const log = await store.get(`actions:${user.id}`);
  assert.equal(log.length, 2);
  assert.equal(log[0].decision, 'block');
  assert.ok(log[0].reasons.includes('invalid_tool'));
  assert.equal(log[1].decision, 'allow');
});
