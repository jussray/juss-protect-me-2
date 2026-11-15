import { test, expect } from '@playwright/test';

// Real local Wrangler/Worker route, no customer key or persistent member state.
test('gateway real-path refuses requests without bearer credentials', async ({ request }) => {
  const missing = await request.post('/gateway/check', {
    data: { content: 'synthetic test only' },
  });
  expect(missing.status()).toBe(401);
  const result = await missing.json();
  expect(result.decision).toBe('block');
  expect(result.reasons).toContain('invalid_key');
  expect(missing.headers()['x-content-type-options']).toBe('nosniff');
});
