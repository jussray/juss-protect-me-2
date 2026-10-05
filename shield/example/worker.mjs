// Example: your existing Worker, wrapped by Protect Me Shield.
// "run_worker_first": true in wrangler.jsonc sends every request (including
// /.env, /.git, ...) through the Shield before static assets answer.
import { createShield } from '../shield.mjs';

const app = {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
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
