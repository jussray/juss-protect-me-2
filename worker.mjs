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

export default createShield(app, {
  service: 'juss-protect-me-2',
  rateLimit: { paths: ['/api', '/api/*'], retryAfterSeconds: 60 },
});
