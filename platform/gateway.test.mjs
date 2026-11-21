import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateCheck } from './gateway.mjs';

let n = 0;
const member = (policy = { tools: ['read_file'] }) => ({ id: `gw-test-${++n}`, plan: 'two', entitlement: 'active', policy });

test('allowlisted tool is allowed', async () => {
  const r = await evaluateCheck(null, member(), { tool: 'read_file' });
  assert.equal(r.decision, 'allow');
  assert.deepEqual(r.reasons, []);
});

test('tool outside the allowlist is blocked', async () => {
  const r = await evaluateCheck(null, member(), { tool: 'delete_repo' });
  assert.equal(r.decision, 'block');
  assert.ok(r.reasons.includes('tool_not_allowed'));
});

for (const [label, body] of [
  ['missing', {}],
  ['empty', { tool: '' }],
  ['whitespace', { tool: '   ' }],
  ['number', { tool: 123 }],
  ['array', { tool: ['delete_repo'] }],
  ['null body', null],
]) {
  test(`${label} tool fails closed with missing_tool`, async () => {
    for (const policy of [{ tools: ['read_file'] }, {}]) {
      const r = await evaluateCheck(null, member(policy), body);
      assert.equal(r.decision, 'block');
      assert.ok(r.reasons.includes('missing_tool'), JSON.stringify(r.reasons));
    }
  });
}

test('member without an allowlist can still use a named, non-denied tool', async () => {
  const r = await evaluateCheck(null, member({}), { tool: 'read_file' });
  assert.equal(r.decision, 'allow');
});

// Deny lists must not be bypassed by case, padding or compatibility forms.
for (const tool of ['Admin', 'ADMIN_panel', 'SHELL_EXEC', ' shell_exec ', 'File_Delete', 'ｓｈｅｌｌ_exec']) {
  test(`default-deny is not bypassed by variant ${JSON.stringify(tool)}`, async () => {
    const r = await evaluateCheck(null, member({}), { tool });
    assert.equal(r.decision, 'block');
    assert.ok(r.reasons.includes('tool_denied_by_default'), JSON.stringify(r.reasons));
  });
}

test('member deny list is matched case-insensitively', async () => {
  const r = await evaluateCheck(null, member({ deniedTools: ['Deploy'] }), { tool: 'DEPLOY' });
  assert.equal(r.decision, 'block');
  assert.ok(r.reasons.includes('tool_denied_by_member'), JSON.stringify(r.reasons));
});

test('allowlist stays exact: a case variant of an allowed tool is not allowed', async () => {
  const r = await evaluateCheck(null, member(), { tool: 'READ_FILE' });
  assert.equal(r.decision, 'block');
  assert.ok(r.reasons.includes('tool_not_allowed'));
});
