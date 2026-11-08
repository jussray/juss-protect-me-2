import { createShield } from './shield/shield.mjs';
import { createIncidentSignalBridge } from './shield/incident-signal-bridge.mjs';
import { createFounderRoom } from './platform/founder-room.mjs';
import { createPayments } from './platform/payments.mjs';
import { createGateway } from './platform/gateway.mjs';
import { createStore, listUsers, statsFromStore } from './platform/store.mjs';

// The public route reports this Worker's deployment only. It does not
// claim to protect external repositories, devices, or unrelated apps.
function createApp(bridge) {
  return {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    // Product platform (founder room, checkout, gateway) — routes are
    // served by this Worker; anything unconfigured answers honestly.
    const store = createStore(env);
    if (pathname === '/founder' || pathname.startsWith('/founder/') || pathname === '/api/founder/state') {
      return createFounderRoom({ statsProvider: () => statsFromStore(store), membersProvider: () => listUsers(store) }).fetch(request, env);
    }
    if (pathname === '/buy' || pathname === '/webhooks/stripe' || pathname === '/checkout' || pathname.startsWith('/checkout/') || pathname === '/account' || pathname === '/account/rotate' || pathname === '/account/policy') {
      return createPayments({ store, onSecurityChange: bridge?.onPrivilegeChange }).fetch(request, env);
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
}

// Deliberately dormant until explicitly provisioned with a separate signer,
// verified source identity and the Cloudflare Queue. No public ingestion route.
function incidentBridgeFor(env) {
  if (env?.INCIDENT_SIGNALS_ENABLED !== 'true') return null;
  return createIncidentSignalBridge({
    service: 'juss-protect-me-2',
    identity: {
      source: {
        repository: 'jussray/juss-protect-me-2',
        branch: env.INCIDENT_SOURCE_BRANCH,
        commitSha: env.INCIDENT_SOURCE_SHA,
      },
      runtime: {
        environment: env.INCIDENT_ENVIRONMENT,
        buildId: env.INCIDENT_BUILD_ID,
      },
    },
    shieldSecret: env.SHIELD_SECRET,
    signingSecret: env.INCIDENT_SIGNING_SECRET,
    sink: env.INCIDENT_EVIDENCE_QUEUE,
  });
}

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
    const bridge = incidentBridgeFor(env);
    const shield = createShield(createApp(bridge), {
      service: 'juss-protect-me-2',
      rateLimit: { paths: ['/api', '/api/*', '/founder/login', '/gateway/check'], retryAfterSeconds: 60 },
      ...(bridge ? { onSecurityAttempt: bridge.onShieldAttempt } : {}),
    });
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
