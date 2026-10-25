import { test, expect } from '@playwright/test';

test('Model Two public welcome page shows value without implementation details', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle('Juss Protect Me 2 | Confidence for what\'s next');
  await expect(page.getByRole('heading', { name: /Imagine more/ })).toBeVisible();
  await page.getByRole('link', { name: 'Explore the vision' }).click();
  await expect(page.getByRole('heading', { name: 'Bold ideas deserve a stronger foundation.' })).toBeVisible();
  await expect(page.getByText(/other products are not automatically covered/)).toBeVisible();
});

test('production Shield reports only its own deployment scope', async ({ request }) => {
  const response = await request.get('/api/status');
  expect(response.status()).toBe(200);
  const data = await response.json();
  expect(data).toMatchObject({
    service: 'juss-protect-me-2',
    component: 'edge-shield',
    scope: 'this-worker-only',
    otherSystemsProtected: false,
  });
  expect(response.headers()['cache-control']).toContain('no-store');
  expect(response.headers()['x-frame-options']).toBe('DENY');
  expect(response.headers()['content-security-policy']).toContain("frame-ancestors 'none'");
});

test('production Shield rejects scanner probes without bypassing headers', async ({ request }) => {
  const response = await request.get('/.env');
  expect(response.status()).toBe(404);
  const data = await response.json();
  expect(data.error).toBe('not_found');
  expect(response.headers()['x-content-type-options']).toBe('nosniff');
  expect(response.headers()['x-frame-options']).toBe('DENY');
});

test('security researchers have an independent reporting entrypoint', async ({ request }) => {
  const response = await request.get('/.well-known/security.txt');
  expect(response.status()).toBe(200);
  const body = await response.text();
  expect(body).toContain('Contact: mailto:security@jussco.company');
  expect(body).toContain('Canonical: https://protect2.jussco.company/.well-known/security.txt');
});
