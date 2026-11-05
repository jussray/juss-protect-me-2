import { test, expect } from '@playwright/test';
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Synthetic member exists only inside Wrangler's --local KV, never production.
const apiKey = 'jp2_' + randomBytes(16).toString('hex');
const memberId = 'playwright-' + randomBytes(8).toString('hex');
const keyHash = createHash('sha256').update(apiKey).digest('hex');
const wrangler = ['--yes', 'wrangler@4.151.0'];
const kvArgs = ['--binding=USERS_KV', '--local', '--config=wrangler.jsonc'];

function localKV(args) {
  return execFileSync('npx', [...wrangler, 'kv', ...args, ...kvArgs], {
    cwd: process.cwd(), encoding: 'utf8', timeout: 90_000,
  });
}

test.beforeAll(() => {
  const folder = mkdtempSync(join(tmpdir(), 'protect-two-gateway-'));
  try {
    const file = join(folder, 'synthetic-kv.json');
    writeFileSync(file, JSON.stringify([
      { key: 'keyhash:' + keyHash, value: JSON.stringify(memberId) },
      { key: 'user:' + memberId, value: JSON.stringify({
        id: memberId, entitlement: 'active',
        apiKeyHash: keyHash, policy: { tools: ['inspect', 'post_social'] },
      }) },
    ]));
    localKV(['bulk', 'put', file]);
  } finally {
    rmSync(folder, { recursive: true, force: true });
  }
});

test('Model Two real Worker gateway authenticates a synthetic member and enforces Sauce Guard', async ({ request }) => {
  const endpoint = '/gateway/check';
  const call = (data) => request.post(endpoint, {
    headers: { Authorization: 'Bearer ' + apiKey },
    data,
  });

  const unauthenticated = await request.post(endpoint, { data: { tool: 'inspect' } });
  expect(unauthenticated.status()).toBe(401);
  expect((await unauthenticated.json()).reasons).toContain('invalid_key');

  const allowed = await call({ tool: 'inspect', content: 'Synthetic internal status report.' });
  expect(allowed.status()).toBe(200);
  expect((await allowed.json()).decision).toBe('allow');

  const missingTool = await call({ content: 'Synthetic internal status report.' });
  expect(missingTool.status()).toBe(200);
  const missingResult = await missingTool.json();
  expect(missingResult.decision).toBe('block');
  expect(missingResult.reasons).toContain('tool_required');

  const disallowed = await call({ tool: 'not_in_member_allowlist' });
  expect((await disallowed.json()).reasons).toContain('tool_not_allowed');

  const publication = await call({
    tool: 'post_social', audience: 'public', founderApproved: true,
    content: 'Synthetic public announcement.',
    claims: [{ state: 'CURRENT', evidenceRef: 'proof://synthetic/123' }],
  });
  const publicationResult = await publication.json();
  expect(publicationResult.decision).toBe('block');
  expect(publicationResult.reasons).toContain('founder_publication_route_required');

  const fakeCredential = 'ghp_' + 'X'.repeat(30);
  const sensitive = await call({ tool: 'inspect', content: 'token=' + fakeCredential });
  expect(sensitive.status()).toBe(200);
  const sensitiveBody = await sensitive.text();
  expect(sensitiveBody).toContain('sauce_guard_content_blocked');
  expect(sensitiveBody).not.toContain(fakeCredential);

  const invalidJson = await request.post(endpoint, {
    headers: { Authorization: 'Bearer ' + apiKey, 'Content-Type': 'application/json' },
    data: '{',
  });
  expect(invalidJson.status()).toBe(400);
  expect((await invalidJson.json()).reasons).toContain('invalid_json');

  const logRaw = localKV(['key', 'get', 'actions:' + memberId]);
  const actions = JSON.parse(logRaw.trim());
  expect(actions.some((entry) => entry.decision === 'allow' && entry.tool === 'inspect')).toBeTruthy();
  expect(actions.some((entry) => entry.decision === 'block' && entry.reasons.includes('tool_required'))).toBeTruthy();
  expect(logRaw).not.toContain(fakeCredential);
});
