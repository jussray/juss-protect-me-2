import { test, expect } from '@playwright/test';

test('Model Two public front door displays approved Juss & Co. artwork with honest early access', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle('Juss & Co. | Protection That Empowers');
  const art = page.locator('img.approved-art');
  await expect(art).toBeVisible();
  await expect(art).toHaveJSProperty('naturalWidth', 1536);
  await page.getByRole('link', { name: 'Explore Model Two Early Access' }).click();
  await expect(page).toHaveURL(/#early-access$/);
  await expect(page.getByRole('heading', { name: 'Get Early Access' })).toBeVisible();
  await expect(page.getByText(/Enrollment is not yet available/)).toBeVisible();
});

test('mobile front door preserves both real people and AI safety journeys', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  await expect(page.locator('.mobile-view')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Real Protection for Real People' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'AI Agent Security for What Comes Next' })).toBeVisible();
  await page.locator('.image-half.two img').scrollIntoViewIfNeeded();
  await expect(page.locator('.image-half.two img')).toHaveJSProperty('naturalWidth', 1536);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  expect(overflow).toBe(false);
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