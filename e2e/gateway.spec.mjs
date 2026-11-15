import { createServer } from 'node:http';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { test, expect } from '@playwright/test';
import { createStore } from '../platform/store.mjs';
import { createGateway } from '../platform/gateway.mjs';

test('gateway real HTTP path rejects incomplete actions and preserves legitimate checks', async ({ request }) => {
  const store = createStore();
  const key = 'jp2_synthetic_playwright_key';
  const user = { id: 'playwright-gateway', entitlement: 'active', policy: {} };
  const hash = createHash('sha256').update(key).digest('hex');
  await store.put(`keyhash:${hash}`, user.id);
  await store.put(`user:${user.id}`, user);
  const gateway = createGateway({ store });

  // Exercise the same Request/Response gateway handler through an actual
  // localhost HTTP connection, without touching customer or production data.
  const server = createServer(async (incoming, outgoing) => {
    try {
      const chunks = [];
      for await (const chunk of incoming) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      const webRequest = new Request(`http://127.0.0.1${incoming.url}`, {
        method: incoming.method,
        headers: incoming.headers,
        ...(body.length ? { body } : {}),
      });
      const response = await gateway.fetch(webRequest, {});
      outgoing.writeHead(response.status, Object.fromEntries(response.headers.entries()));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      outgoing.writeHead(500);
      outgoing.end('gateway test transport failed');
    }
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  const url = `http://127.0.0.1:${address.port}/gateway/check`;
  const headers = { Authorization: `Bearer ${key}` };

  try {
    const missing = await request.post(url, { headers, data: { content: 'ordinary text' } });
    expect(missing.status()).toBe(200);
    const denied = await missing.json();
    expect(denied.decision).toBe('block');
    expect(denied.reasons).toContain('invalid_tool');

    const admin = await request.post(url, { headers, data: { tool: 'AdMiN:grant' } });
    expect((await admin.json()).reasons).toContain('tool_denied_by_default');

    const valid = await request.post(url, { headers, data: { tool: 'search.read' } });
    expect(valid.status()).toBe(200);
    expect((await valid.json()).decision).toBe('allow');

    const log = await store.get(`actions:${user.id}`);
    expect(log.map(({ decision }) => decision)).toEqual(['block', 'block', 'allow']);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
