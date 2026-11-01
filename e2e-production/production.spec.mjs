import { test, expect } from '@playwright/test';

test('Model Two is its own violet site, with only AI protection benefits', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle('Juss Protect Me 2 | Juss & Co.');
  await expect(page.getByRole('heading', { name: /AI Agent Security.*for What Comes Next/ })).toBeVisible();
  await expect(page.locator('.feature-card')).toHaveCount(4);
  await expect(page.getByRole('heading', { name: 'AI Agent Control' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Trusted Tools' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Content Safety' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Action Insights' })).toBeVisible();
  await expect(page.getByRole('heading', { name: /Real Protection for Real People/ })).toHaveCount(0);
  await expect(page.locator('svg.portrait-picture')).toBeVisible();
  await expect(page.locator('svg.feature-picture')).toHaveCount(4);
  // The current public CTA goes to the site's checkout entry point, not a page anchor.
  await expect(page.locator('#early-access')).toBeVisible();
  await page.getByRole('link', { name: /Join Early Access/ }).click();
  await expect(page).toHaveURL(/\/checkout$/);
  await expect(page.getByRole('heading', { name: 'Enrollment opens at launch' })).toBeVisible();
});

test('Model Two narrow and standard phones preserve identity and a gated checkout', async ({ page }) => {
  for (const [width, height] of [[320, 740], [390, 844]]) {
    await page.setViewportSize({ width, height });
    const home = await page.goto('/');
    expect(home?.status()).toBe(200);
    await expect(page).toHaveTitle('Juss Protect Me 2 | Juss & Co.');
    await expect(page.locator('.hero-portrait')).toBeVisible();
    await expect(page.getByRole('heading', { name: /AI Agent Security.*for What Comes Next/ })).toBeVisible();
    await expect(page.locator('.feature-card')).toHaveCount(4);
    await expect(page.getByRole('heading', { name: 'Device Safety' })).toHaveCount(0);
    const sizes = await page.evaluate(() => ({
      documentWidth: document.documentElement.scrollWidth,
      viewportWidth: document.documentElement.clientWidth,
    }));
    expect(sizes.documentWidth).toBeLessThanOrEqual(sizes.viewportWidth + 1);
    const join = page.getByRole('link', { name: /Join Early Access/ });
    await expect(join).toHaveAttribute('href', '/checkout');
    await page.screenshot({ path: `test-results/model-two-mobile-${width}.png` });
    await join.click();
    await expect(page).toHaveURL((url) => url.pathname === '/checkout');
    await expect(page.getByRole('heading', { name: 'Enrollment opens at launch' })).toBeVisible();
  }
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