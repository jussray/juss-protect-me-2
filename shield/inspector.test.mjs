import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectCrawlerRequest, INSPECTION_SCHEMA } from './inspector.mjs';
import { verifyReceipt } from './shield.mjs';

const input = (extra = {}) => ({
  method: 'GET',
  pathname: '/work',
  userAgent: 'Googlebot/2.1',
  verifiedBot: false,
  botScore: null,
  asn: null,
  country: null,
  ...extra,
});

test('signed inspection distinguishes claimed and edge-verified crawlers', async () => {
  const secret = 'test-only-signer';
  const claimed = await inspectCrawlerRequest(input(), secret);
  assert.equal(claimed.schema, INSPECTION_SCHEMA);
  assert.equal(claimed.action, 'pass');
  assert.equal(claimed.verdict, 'CLAIMED_CRAWLER');
  assert.equal(claimed.receiptKind, 'hmac-sha256');
  assert.equal(await verifyReceipt(claimed.evidence, secret), true);
  assert.equal(claimed.evidence.event.pathname, '[redacted]');
  assert.equal(claimed.evidence.event.identity.userAgent, null);
  assert.equal(claimed.evidence.event.identity.actor, null);
  const verified = await inspectCrawlerRequest(input({ verifiedBot: true, botScore: 92 }), secret);
  assert.equal(verified.action, 'pass');
  assert.equal(verified.verdict, 'VERIFIED_BOT');
});

test('probe denied, ordinary reader passes, missing key grants no authority', async () => {
  const probe = await inspectCrawlerRequest(input({ pathname: '/.env', userAgent: 'curl/9.0' }), 'test-only-signer');
  assert.equal(probe.action, 'deny');
  assert.equal(probe.verdict, 'PROBE');
  const normal = await inspectCrawlerRequest(input({ userAgent: 'Mozilla/5.0' }), 'test-only-signer');
  assert.equal(normal.action, 'pass');
  assert.equal(normal.verdict, 'NORMAL');
  const unsigned = await inspectCrawlerRequest(input(), undefined);
  assert.equal(unsigned.action, 'unverified');
  assert.equal(unsigned.receiptKind, 'none');
});

test('rejects unbounded and invalid inspection metadata', async () => {
  for (const extra of [
    { pathname: 'https://attacker.invalid/x' },
    { pathname: '/work?token=secret' },
    { userAgent: 'x'.repeat(257) },
    { verifiedBot: 'true' },
    { botScore: -1 },
    { asn: -1 },
    { country: 'INVALID' },
  ]) {
    await assert.rejects(() => inspectCrawlerRequest(input(extra), 'secret'), /INPUT_INVALID/);
  }
});
