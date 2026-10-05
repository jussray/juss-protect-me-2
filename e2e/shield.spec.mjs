/* global fetch */
import { test, expect } from '@playwright/test';

test('real Worker: page loads, probes get the decoy, /api is rate limited without bypass', async ({ page }) => {
  const home = await page.goto('/');
  expect(home?.status()).toBe(200);
  await expect(page.locator('#status')).toHaveText('Protected by Protect Me Shield');

  const proof = await page.evaluate(async () => {
    const probe = await fetch('/.env', { cache: 'no-store' });
    const gitProbe = await fetch('/.git/config', { cache: 'no-store' });
    const statuses = [];
    let retryAfter = null;
    let body = null;
    for (let i = 0; i < 80; i += 1) {
      const r = await fetch('/api/hello', { cache: 'no-store' });
      statuses.push(r.status);
      if (r.status === 429) {
        retryAfter = r.headers.get('retry-after');
        body = await r.json();
        break;
      }
    }
    const exactRoot = await fetch('/api', { cache: 'no-store' });
    const staticAfter = await fetch('/', { cache: 'no-store' });
    return {
      probeStatus: probe.status,
      probeBody: await probe.json(),
      probeCache: probe.headers.get('cache-control'),
      gitProbeStatus: gitProbe.status,
      firstApi: statuses[0],
      statuses,
      retryAfter,
      body,
      exactRootStatus: exactRoot.status,
      staticStatus: staticAfter.status,
    };
  });

  expect(proof.probeStatus).toBe(404);
  expect(proof.probeBody).toEqual({ error: 'not_found' });
  expect(proof.probeCache).toBe('no-store');
  expect(proof.gitProbeStatus).toBe(404);
  expect(proof.firstApi).toBe(200);
  expect(proof.statuses).toContain(429);
  expect(proof.retryAfter).toBe('60');
  expect(proof.body).toEqual({ ok: false, error: 'rate_limit_exceeded' });
  expect(proof.exactRootStatus).toBe(429);
  expect(proof.staticStatus).toBe(200);
});
