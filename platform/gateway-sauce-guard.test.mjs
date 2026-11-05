import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateCheck } from './gateway.mjs';

const user = {
  id: 'synthetic-member', entitlement: 'active',
  policy: { tools: ['inspect', 'post_social'] },
};
test('Model Two gateway passes ordinary internal member inspection', async () => {
  const checked = await evaluateCheck(null, user, { tool: 'inspect', content: 'Synthetic nonsecret report' });
  assert.equal(checked.decision, 'allow');
});
test('Model Two gateway rejects sensitive outbound content without logging values', async () => {
  const secret = 'ghp_' + 'X'.repeat(30);
  const checked = await evaluateCheck(null, user, { tool: 'inspect', content: 'value=' + secret });
  assert.equal(checked.decision, 'block');
  assert.ok(checked.reasons.includes('sauce_guard_content_blocked'));
  assert.equal(JSON.stringify(checked).includes(secret), false);
});
test('Model Two gateway does not treat safe screening or claimed approval as publish authority', async () => {
  const checked = await evaluateCheck(null, user, {
    tool: 'post_social', audience: 'public',
    content: 'We improved the synthetic service.',
    claims: [{ state: 'CURRENT', evidenceRef: 'proof://approved/public/123' }],
    founderApproved: true,
  });
  assert.equal(checked.decision, 'block');
  assert.ok(checked.reasons.includes('founder_publication_route_required'));
});
test('Model Two gateway blocks unknown claims and omitted tool audience on outbound action', async () => {
  const unknown = await evaluateCheck(null, user, {
    tool: 'inspect', audience: 'public', content: 'Synthetic outcome',
    claims: [{ state: 'UNKNOWN' }],
  });
  assert.equal(unknown.decision, 'block');
  assert.ok(unknown.reasons.includes('sauce_guard_content_blocked'));
  const undeclared = await evaluateCheck(null, user, {
    tool: 'post_social', content: 'Synthetic outcome',
  });
  assert.ok(undeclared.reasons.includes('founder_publication_route_required'));
});
