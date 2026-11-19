import { WorkerEntrypoint } from 'cloudflare:workers';
import { inspectCrawlerRequest } from './shield/inspector.mjs';
import { createShield } from './shield/shield.mjs';
import { createFounderRoom } from './platform/founder-room.mjs';
import { createPayments } from './platform/payments.mjs';
import { createGateway } from './platform/gateway.mjs';
import { createStore, listUsers, statsFromStore } from './platform/store.mjs';

// The public route reports this Worker's deployment only. It does not
// claim to protect external repositories, devices, or unrelated apps.
const app = {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    // Product platform (founder room, checkout, gateway) — routes are
    // served by this Worker; anything unconfigured answers honestly.
    const store = createStore(env);
    if (pathname === '/founder' || pathname.startsWith('/founder/') || pathname === '/api/founder/state') {
      return createFounderRoom({ statsProvider: () => statsFromStore(store), membersProvider: () => listUsers(store) }).fetch(request, env);
    }
    if (pathname === '/buy' || pathname === '/webhooks/stripe' || pathname === '/checkout' || pathname.startsWith('/checkout/') || pathname === '/account' || pathname === '/account/rotate' || pathname === '/account/policy') {
      return createPayments({ store }).fetch(request, env);
    }
    if (pathname === '/gateway/check' || pathname === '/account/actions') {
      return createGateway({ store }).fetch(request, env);
    }
    if (request.method === 'GET' && pathname === '/api/status') {
      return Response.json({
        service: 'juss-protect-me-2',
        component: 'edge-shield',
        scope: 'this-worker-only',
        state: 'serving',
        otherSystemsProtected: false,
      }, { headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
    }
    if (pathname === '/api' || pathname.startsWith('/api/')) {
      return new Response('Not found', { status: 404 });
    }
    return env.ASSETS.fetch(request);
  },
};

const shield = createShield(app, {
  service: 'juss-protect-me-2',
  rateLimit: { paths: ['/api', '/api/*', '/founder/login', '/gateway/check'], retryAfterSeconds: 60 },
});

// Keep response hardening outside Shield so decoys, limiter failures,
// API responses, and static assets receive the same security headers.
const RESPONSE_HEADERS = Object.freeze({
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=31536000',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'Content-Security-Policy': "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests",
});

export default {
  async fetch(request, env, ctx) {
    const result = await shield.fetch(request, env, ctx);
    const headers = new Headers(result.headers);
    for (const [key, value] of Object.entries(RESPONSE_HEADERS)) {
      headers.set(key, value);
    }
    const path = new URL(request.url).pathname;
    if (path === '/founder' || path.startsWith('/founder/') || path === '/checkout' || path.startsWith('/checkout/') || path === '/buy' || path === '/account' || path === '/account/rotate' || path === '/account/policy') {
      headers.set('Content-Security-Policy', "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests");
    }
    if (path === '/api' || path.startsWith('/api/')) {
      headers.set('Cache-Control', 'no-store');
    }
    return new Response(result.body, {
      status: result.status,
      statusText: result.statusText,
      headers,
    });
  },
};

// Invokable only through a Cloudflare service binding to this named entrypoint.
// No new public HTTP route or crawler trust bypass is created.
export class ShieldInspector extends WorkerEntrypoint {
  async inspect(input) {
    const result = await inspectCrawlerRequest(input, this.env?.SHIELD_SECRET);
    if (result.evidence && result.verdict !== 'NORMAL') {
      console.log('[protect-me-shield-inspector]', JSON.stringify(result.evidence));
    }
    const { evidence, ...response } = result;
    return response;
  }
}
