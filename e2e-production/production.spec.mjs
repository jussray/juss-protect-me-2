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
    const socialLinks = [
      ['Juss & Co. on Instagram', 'https://www.instagram.com/jussnco/'],
      ['Juss Ray on YouTube', 'https://www.youtube.com/channel/UCpEsqUi3uDpiNonJuu1hOKQ'],
      ['Juss Rayy on LinkedIn', 'https://www.linkedin.com/in/juss-rayy-13ba691a1'],
    ];
    await expect(page.locator('.socials a')).toHaveCount(socialLinks.length);
    for (const [name, href] of socialLinks) {
      const link = page.getByRole('link', { name, exact: true });
      await expect(link).toHaveAttribute('href', href);
      await expect(link).toHaveAttribute('target', '_blank');
      await expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    }
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

test('Model Two About explains real scope and exposes search metadata on mobile', async ({ page }) => {
  for (const width of [320, 390, 1280]) {
    await page.setViewportSize({ width, height: 800 });
    const response = await page.goto('/about.html');
    expect(response?.status()).toBe(200);
    await expect(page).toHaveTitle('About Juss Protect Me 2 | AI Agent Security | Juss & Co.');
    await expect(page.getByRole('heading', { level: 1, name: /About Juss Protect Me 2: AI agent security/ })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Who is Model Two for?' })).toBeVisible();
    await expect(page.getByText(/visiting this website alone does not activate protection/i)).toBeVisible();
    await expect(page.locator('link[rel="canonical"]')).toHaveAttribute('href', 'https://protect2.jussco.company/about.html');
    await expect(page.locator('meta[name="description"]')).toHaveAttribute('content', /AI-agent security project/);
    const data = JSON.parse(await page.locator('script[type="application/ld+json"]').textContent());
    expect(data['@graph'].find((entry) => entry['@type'] === 'AboutPage')?.mainEntity?.['@id']).toBe('https://protect2.jussco.company/#product');
    await expect(page.getByRole('link', { name: /Juss Protect Me \(Model One\)/ })).toHaveAttribute('href', 'https://protect.jussco.company/about.html');
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
    expect(overflow).toBe(false);
    await page.screenshot({ path: `test-results/model-two-about-${width}.png` });
  }
});


test('Model Two product catalog is independent and does not promise external protection', async ({ page }) => {
  for (const width of [320, 390, 1280]) {
    await page.setViewportSize({ width, height: 820 });
    await page.goto('/');
    await page.getByRole('navigation', { name: 'Primary navigation' }).getByRole('link', { name: 'Products' }).click();
    await expect(page).toHaveURL(/\/products\.html$/);
    await expect(page.locator('.cards .card')).toHaveCount(4);
    for (const title of ['Agent Permissions', 'Website & API Shield', 'Safe Code Releases', 'Evidence & Recovery']) {
      await expect(page.getByRole('heading', { name: title })).toBeVisible();
    }
    await expect(page.getByText('Protecting this site only')).toBeVisible();
    await expect(page.getByText(/Other websites are not automatically covered/)).toBeVisible();
    await expect(page.locator('link[rel="canonical"]')).toHaveAttribute('href', 'https://protect2.jussco.company/products.html');
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(1);
    await page.screenshot({ path: `test-results/model-two-products-${width}.png` });
  }
});

test('all four Model Two cards open distinct, honest product details on mobile and desktop', async ({ page }) => {
  const cards = [
    ['AI Agent Control', 'agent-control'],
    ['Trusted Tools', 'trusted-tools'],
    ['Content Safety', 'content-safety'],
    ['Action Insights', 'action-insights'],
  ];
  for (const width of [320, 390, 1280]) {
    await page.setViewportSize({ width, height: 820 });
    for (const [label, slug] of cards) {
      await page.goto('/');
      const link = page.getByRole('link', { name: `Explore ${label} protection details` });
      await expect(link).toHaveAttribute('href', `/products.html#${slug}`);
      await link.click();
      await expect(page).toHaveURL(new RegExp(`/products\\.html#${slug}$`));
      const section = page.locator(`#${slug}`);
      await expect(section).toBeVisible();
      await expect(section.getByRole('heading', { name: label })).toBeVisible();
      const onscreen = await section.evaluate(el => {
        const bounds = el.getBoundingClientRect();
        return bounds.top < window.innerHeight && bounds.bottom > 0;
      });
      expect(onscreen).toBe(true);
    }
  }
});
