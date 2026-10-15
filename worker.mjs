import { createShield } from './shield/shield.mjs';

// The public route reports this Worker's deployment only. It does not
// claim to protect external repositories, devices, or unrelated apps.
const app = {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
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
  rateLimit: { paths: ['/api', '/api/*'], retryAfterSeconds: 60 },
});

// Keep response hardening outside Shield so decoys, limiter failures,
// API responses, and static assets receive the same security headers.
const RESPONSE_HEADERS = Object.freeze({
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=31536000',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests",
});

export default {
  async fetch(request, env, ctx) {
    const result = await shield.fetch(request, env, ctx);
    const headers = new Headers(result.headers);
    for (const [key, value] of Object.entries(RESPONSE_HEADERS)) {
      headers.set(key, value);
    }
    const path = new URL(request.url).pathname;
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
