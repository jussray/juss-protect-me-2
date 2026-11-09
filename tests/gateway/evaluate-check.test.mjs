import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateCheck, createGateway } from '../../platform/gateway.mjs';

let nextId = 0;
function user(overrides = {}) {
  return { id: 'gateway-test-' + (++nextId), entitlement: 'active',
    policy: { tools: ['report.generate'] }, ...overrides };
}
test('missing, blank, and non-string tool identifiers fail closed', async () => {
  for (const body of [{}, {tool:''}, {tool:'   '}, {tool:null}, {tool:42}, {tool:{}}, {tool:[]}, {tool:true}]) {
    const result = await evaluateCheck(null, user(), body);
    assert.equal(result.decision, 'block', JSON.stringify(body));
    assert.ok(result.reasons.includes('missing_tool'), JSON.stringify(body));
  }
});
test('unknown tool is rejected by the allowlist', async () => {
  const r = await evaluateCheck(null, user(), {tool:'unknown'});
  assert.equal(r.decision, 'block');
  assert.ok(r.reasons.includes('tool_not_allowed'));
  assert.ok(!r.reasons.includes('missing_tool'));
});
test('allowed tool remains allowed; tool whitespace normalizes', async () => {
  const r = await evaluateCheck(null, user(), {tool:' report.generate '});
  assert.equal(r.decision, 'allow');
  assert.equal(r.tool, 'report.generate');
});
test('inactive entitlement and default-denied tools remain blocked', async () => {
  assert.equal((await evaluateCheck(null, user({entitlement:'suspended'}), {tool:'report.generate'})).decision, 'block');
  assert.ok((await evaluateCheck(null, user({policy:{tools:['shell_exec']}}), {tool:'shell_exec'})).reasons.includes('tool_denied_by_default'));
});
test('credential patterns and payload limits remain blocked', async () => {
  assert.ok((await evaluateCheck(null, user(), {tool:'report.generate', content:'password=example'})).reasons.includes('credential_content_blocked'));
  assert.ok((await evaluateCheck(null, user(), {tool:'report.generate', content:'x'.repeat(65537)})).reasons.includes('payload_too_large'));
});
test('HTTP gateway refuses absent authorization before evaluating a tool', async () => {
  const store = { get: async () => null, put: async () => {} };
  const gateway = createGateway({store});
  const response = await gateway.fetch(new Request('https://example.invalid/gateway/check', {
    method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({tool:'report.generate'})
  }), {});
  assert.equal(response.status, 401);
  const data = await response.json();
  assert.equal(data.decision, 'block');
  assert.ok(data.reasons.includes('invalid_key'));
});
