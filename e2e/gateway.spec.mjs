import { test, expect } from '@playwright/test';

// This Playwright suite runs against shield/example/wrangler.jsonc.
// The standalone Shield example must not claim to serve the member gateway.
test('standalone Shield fixture does not expose member gateway', async ({ request }) => {
  const response = await request.post('/gateway/check', {
    data: { tool: 'report.generate', content: 'synthetic fixture only' },
  });
  expect(response.status()).toBe(404);
});
