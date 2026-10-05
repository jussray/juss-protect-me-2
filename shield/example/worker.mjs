// Example: your existing Worker, wrapped by Protect Me Shield.
// "run_worker_first": true in wrangler.jsonc sends every request (including
// /.env, /.git, ...) through the Shield before static assets answer.
import { createShield } from '../shield.mjs';

const app = {
  async fetch(request, env) {
    // Decode like popular routers (Hono, itty) do — this is what made
    // "/%61pi" reach /api before the Shield canonicalized paths.
    let { pathname } = new URL(request.url);
    try { pathname = decodeURIComponent(pathname).toLowerCase(); } catch { /* keep raw */ }
    if (pathname === '/api' || pathname.startsWith('/api/')) {
      return Response.json({ ok: true, path: pathname });
    }
    return env.ASSETS.fetch(request);
  },
};

export default createShield(app, {
  service: 'example',
  rateLimit: { paths: ['/api', '/api/*'], retryAfterSeconds: 60 },
});
