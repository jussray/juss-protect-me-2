import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classify, createShield, matchPath, nodeRequestInput, rateLimit, resolveConfig, verifyReceipt,
} from './shield.mjs';

const upstream = { fetch: async () => new Response('app', { status: 200 }) };
const limiterThatAllows = (n) => {
  let used = 0;
  return { limit: async () => ({ success: ++used <= n }) };
};
const req = (path, init = {}) => new Request(`https://example.test${path}`, init);

test('path matching: exact roots and wildcard subtrees, nothing looser', () => {
  assert.equal(matchPath('/api', ['/api', '/api/*']), true);
  assert.equal(matchPath('/api/x/y', ['/api/*']), true);
  assert.equal(matchPath('/apix', ['/api', '/api/*']), false);
  assert.equal(matchPath('/api', ['/api/*']), false);
});

test('rate limit fails closed when the binding is missing', async () => {
  const res = await rateLimit(req('/api/x'), {});
  assert.equal(res.status, 503);
  assert.deepEqual(await res.json(), { ok: false, error: 'rate_limit_unavailable' });
});

test('rate limit returns 429 with Retry-After once exhausted; non-dynamic paths are untouched', async () => {
  const env = { SHIELD_RATE_LIMITER: limiterThatAllows(1) };
  assert.equal(await rateLimit(req('/api'), env), null);
  const res = await rateLimit(req('/api'), env);
  assert.equal(res.status, 429);
  assert.equal(res.headers.get('retry-after'), '60');
  assert.equal(await rateLimit(req('/index.html'), env), null);
});

test('rate limit key ignores client-controlled forwarding headers', async () => {
  const keys = [];
  const env = { SHIELD_RATE_LIMITER: { limit: async ({ key }) => { keys.push(key); return { success: true }; } } };
  await rateLimit(req('/api', { headers: { 'x-forwarded-for': '1.2.3.4' } }), env);
  await rateLimit(req('/api', { headers: { 'cf-connecting-ip': '5.6.7.8' } }), env);
  assert.deepEqual(keys, ['ip:unknown', 'ip:5.6.7.8']);
});

test('config is per customer: binding, paths and Retry-After are all overridable', async () => {
  const cfg = resolveConfig({ rateLimit: { binding: 'RL', paths: ['/graphql'], retryAfterSeconds: 30 } });
  const env = { RL: limiterThatAllows(0) };
  const res = await rateLimit(req('/graphql'), env, cfg);
  assert.equal(res.headers.get('retry-after'), '30');
  assert.equal(await rateLimit(req('/api'), env, cfg), null);
});

test('probe paths get an inert decoy and never reach the app', async () => {
  let reached = false;
  const shield = createShield({ fetch: async () => { reached = true; return new Response('app'); } });
  const res = await shield.fetch(req('/.env'), {}, {});
  assert.equal(res.status, 404);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await res.json(), { error: 'not_found' });
  assert.equal(reached, false);
});

test('normal traffic passes through unchanged', async () => {
  const shield = createShield(upstream);
  const res = await shield.fetch(req('/'), {}, {});
  assert.equal(await res.text(), 'app');
});

test('a claimed crawler is not trusted without Cloudflare verification', async () => {
  const o = await classify({ method: 'GET', url: '/', userAgent: 'Googlebot/2.1' });
  assert.equal(o.event.verdict, 'CLAIMED_CRAWLER');
  assert.equal(o.checks.find((c) => c.check === 'identity-claim').result, 'UNVERIFIED_CLAIM');
  const v = await classify({ method: 'GET', url: '/', userAgent: 'Googlebot/2.1', cf: { botManagement: { verifiedBot: true } } });
  assert.equal(v.event.verdict, 'VERIFIED_BOT');
});

test('checks are computed, not constant: clean traffic and probes differ', async () => {
  const clean = await classify({ method: 'GET', url: '/', userAgent: 'Mozilla/5.0' });
  const probe = await classify({ method: 'GET', url: '/wp-admin', userAgent: 'sqlmap' });
  assert.equal(clean.notable, false);
  assert.ok(clean.checks.every((c) => c.result === 'PASS' || c.result === 'UNKNOWN_ACTOR'));
  assert.equal(probe.checks.find((c) => c.check === 'probe-path').result, 'DECOY');
  assert.equal(probe.checks.find((c) => c.check === 'automation').result, 'FLAGGED');
});

test('raw IPs are never stored; actor id needs a server secret', async () => {
  const none = await classify({ method: 'GET', url: '/', sourceIp: '203.0.113.9' });
  assert.equal(none.event.identity.actor, null);
  assert.equal(JSON.stringify(none).includes('203.0.113.9'), false);
  const withSecret = await classify({ method: 'GET', url: '/', sourceIp: '203.0.113.9' }, undefined, 's3cret');
  assert.match(withSecret.event.identity.actor, /^[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(withSecret).includes('203.0.113.9'), false);
});

test('HMAC receipts verify with the right secret and fail on tamper or wrong secret', async () => {
  const o = await classify({ method: 'GET', url: '/.git/config', userAgent: 'curl/8' }, undefined, 'k1');
  assert.equal(o.receiptKind, 'hmac-sha256');
  assert.equal(await verifyReceipt(o, 'k1'), true);
  assert.equal(await verifyReceipt(o, 'k2'), false);
  const tampered = { ...o, event: { ...o.event, verdict: 'NORMAL' } };
  assert.equal(await verifyReceipt(tampered, 'k1'), false);
});

test('Node adapter distrusts forwarding headers unless trustProxy is set', () => {
  const r = { method: 'GET', url: '/', headers: { 'x-forwarded-for': '6.6.6.6, 10.0.0.1' }, socket: { remoteAddress: '10.0.0.1' } };
  assert.equal(nodeRequestInput(r).sourceIp, '10.0.0.1');
  assert.equal(nodeRequestInput(r, { trustProxy: true }).sourceIp, '6.6.6.6');
});

test('TRACE and CONNECT are treated as probes', async () => {
  assert.equal((await classify({ method: 'TRACE', url: '/' })).event.verdict, 'PROBE');
});

test('encoded, upper-case and double-slash variants cannot dodge the rate limit', async () => {
  const env = { SHIELD_RATE_LIMITER: limiterThatAllows(0) };
  for (const p of ['/%61pi/x', '/API/x', '//api/x', '/%2561pi', '/ap%69', '/Api']) {
    assert.equal((await rateLimit(req(p), env))?.status, 429, p);
  }
  assert.equal(await rateLimit(req('/apix'), env), null);
});

test('dot-file probes are caught anywhere in the path and in variants', async () => {
  const shield = createShield(upstream);
  for (const p of ['/.env.local', '/.env.bak', '/%2eenv', '//.env', '/foo/.env', '/backup/.git/config', '/.ENV']) {
    assert.equal((await shield.fetch(req(p), {}, {})).status, 404, p);
  }
  assert.equal(await (await shield.fetch(req('/environment'), {}, {})).text(), 'app');
});

test('custom probe paths match case-insensitively', async () => {
  const shield = createShield(upstream, { probePaths: ['/Admin'] });
  assert.equal((await shield.fetch(req('/Admin'), {}, {})).status, 404);
  assert.equal((await shield.fetch(req('/admin/x'), {}, {})).status, 404);
});

test('a limiter that throws or answers nonsense fails closed with 503', async () => {
  for (const limit of [async () => { throw new Error('kv down'); }, async () => undefined, async () => ({})]) {
    const res = await rateLimit(req('/api'), { SHIELD_RATE_LIMITER: { limit } });
    assert.equal(res.status, 503);
    assert.deepEqual(await res.json(), { ok: false, error: 'rate_limit_unavailable' });
  }
});

test('malformed config is rejected at startup, not on every request', () => {
  assert.throws(() => createShield(upstream, { rateLimit: { paths: '/api/*' } }), /rateLimit.paths/);
  assert.throws(() => createShield(upstream, { probePaths: ['admin'] }), /probePaths/);
  assert.throws(() => createShield(upstream, { rateLimit: { retryAfterSeconds: 0 } }), /retryAfterSeconds/);
});
