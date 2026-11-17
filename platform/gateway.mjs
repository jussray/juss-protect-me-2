// Juss Protect Me Two — the gateway: the checkpoint a member's key plugs into.
// Every agent action passes here BEFORE it runs:
//   key valid? -> membership active? -> tool inside the member's boundaries?
//   -> content clean of credential leaks? -> rate within limits?
// Answer is allow or block, with plain reasons, and every check is written
// to the member's action log (the "Action Insights" from the product page).
// Honest scope: the content screen is pattern-based (credential/exfiltration
// shapes). It is a real boundary, not a promise to catch everything.
import { accountToken, readAccountToken } from './payments.mjs';

const enc = new TextEncoder();
function hex(bytes) { return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join(''); }
async function sha256Hex(msg) { return hex(await crypto.subtle.digest('SHA-256', enc.encode(msg))); }

const DEFAULT_DENIED_TOOLS = ['shell_exec', 'code_exec', 'file_delete', 'payment_send', 'admin'];
const CREDENTIAL_PATTERNS = [
  /(?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*\S+/i,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{8,}/,
  /\bghp_[A-Za-z0-9]{20,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
];
const RATE_LIMIT = 60; // checks per minute per member
const windows = new Map();
// Tool names follow the same rule as the member's policy lists, with a length cap,
// so a policed agent cannot write newlines or huge values into its own audit log.
const TOOL_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.:-]*$/;
const TOOL_NAME_MAX = 128;
// One KV key per log entry: concurrent checks never overwrite each other.
// Inverted timestamp makes ascending key order newest-first.
// Entries expire after 14 days: one key per check is otherwise unbounded storage.
const ACTION_TTL_S = 14 * 24 * 60 * 60;
const actionPrefix = (userId) => `action:${userId}:`;
function actionKey(userId, now) {
  const inv = String(9999999999999 - now).padStart(13, '0');
  const rand = [...crypto.getRandomValues(new Uint8Array(4))].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${actionPrefix(userId)}${inv}:${rand}`;
}

function rateLimited(userId) {
  const now = Date.now();
  const list = (windows.get(userId) || []).filter((t) => now - t < 60000);
  list.push(now);
  windows.set(userId, list);
  return list.length > RATE_LIMIT;
}

export async function findUserByKey(store, apiKey) {
  if (!apiKey || !apiKey.startsWith('jp2_')) return null;
  const hash = await sha256Hex(apiKey);
  const indexed = await store.get(`keyhash:${hash}`);
  // Only the keyhash index resolves keys. There is no fallback scan of every
  // member, so an unknown key costs one read, not one read per member.
  return indexed ? store.get(`user:${indexed}`) : null;
}

// Per-member limit: the Cloudflare rate-limit binding when bound, else the
// in-isolate window (local/tests). The binding is approximate and counts per
// Cloudflare location, not worldwide; a strict global limit needs a Durable Object.
async function memberRateReason(env, userId) {
  const limiter = env?.GATEWAY_MEMBER_LIMITER;
  if (!limiter || typeof limiter.limit !== 'function') return rateLimited(userId) ? 'rate_limit' : null;
  try {
    const { success } = await limiter.limit({ key: `member:${userId}` });
    return success ? null : 'rate_limit';
  } catch {
    return 'rate_limit_unavailable';
  }
}

export async function evaluateCheck(store, user, body, env) {
  const reasons = [];
  if (user.entitlement !== 'active') reasons.push(`membership_${user.entitlement}`);
  const rate = await memberRateReason(env, user.id);
  if (rate) reasons.push(rate);
  const tool = typeof body?.tool === 'string' ? body.tool : '';
  // Fail closed: every action must name its tool. A missing, empty or
  // non-string tool would otherwise skip every boundary check below.
  if (!tool.trim()) reasons.push('missing_tool');
  else if (tool.length > TOOL_NAME_MAX || !TOOL_NAME_RE.test(tool)) reasons.push('invalid_tool');
  const policy = user.policy || {};
  if (Array.isArray(policy.tools) && tool && !policy.tools.includes(tool)) reasons.push('tool_not_allowed');
  // Deny lists match a canonical form (NFKC, trimmed, lower-case) so case,
  // padding or full-width variants cannot slip past them. The allowlist above
  // stays exact, which is the stricter direction.
  const canon = (s) => String(s).normalize('NFKC').trim().toLowerCase();
  const toolKey = canon(tool);
  if (toolKey && DEFAULT_DENIED_TOOLS.some((d) => toolKey === d || toolKey.startsWith('admin'))) reasons.push('tool_denied_by_default');
  if (Array.isArray(policy.deniedTools) && policy.deniedTools.some((d) => canon(d) === toolKey)) reasons.push('tool_denied_by_member');
  const content = typeof body?.content === 'string' ? body.content : '';
  if (content.length > 65536) reasons.push('payload_too_large');
  if (CREDENTIAL_PATTERNS.some((re) => re.test(content))) reasons.push('credential_content_blocked');
  const loggableTool = tool && tool.length <= TOOL_NAME_MAX && TOOL_NAME_RE.test(tool) ? tool : null;
  return { decision: reasons.length ? 'block' : 'allow', reasons, tool: loggableTool };
}

export function createGateway({ store }) {
  return {
    async fetch(request, env) {
      const url = new URL(request.url);
      if (url.pathname === '/gateway/check' && request.method === 'POST') {
        const auth = request.headers.get('Authorization') || '';
        const key = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
        const user = await findUserByKey(store, key);
        if (!user) return Response.json({ decision: 'block', reasons: ['invalid_key'] }, { status: 401 });
        let body = {};
        try { body = await request.json(); } catch { return Response.json({ decision: 'block', reasons: ['invalid_json'] }, { status: 400 }); }
        const result = await evaluateCheck(store, user, body, env);
        const now = Date.now();
        // Every check is recorded. If the record cannot be written, fail closed:
        // an action the member cannot see afterwards is not allowed to proceed.
        try {
          await store.put(actionKey(user.id, now), { at: now, tool: result.tool || null, decision: result.decision, reasons: result.reasons }, { expirationTtl: ACTION_TTL_S });
        } catch (err) {
          // Record the cause (member id + error message only, never the request body).
          console.error('gateway: action log write failed', { userId: user.id, error: String(err?.message || err).slice(0, 200) });
          return Response.json({ decision: 'block', reasons: ['audit_unavailable'], checkedAt: new Date().toISOString() }, { status: 503 });
        }
        return Response.json({ decision: result.decision, reasons: result.reasons, checkedAt: new Date().toISOString() });
      }
      if (url.pathname === '/account/actions' && request.method === 'GET') {
        const userId = await readAccountToken(env, url.searchParams.get('token') || '', store);
        const user = userId ? await store.get(`user:${userId}`) : null;
        if (!user) return new Response('Account link not recognized.', { status: 404 });
        const keys = await store.list(actionPrefix(user.id), 50);
        const log = (await Promise.all(keys.map((k) => store.get(k)))).filter(Boolean);
        if (!log.length) return new Response('No actions checked yet. When your agents act through the gateway, each check appears here in plain language.', { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
        const lines = log.map((e) =>
          `${new Date(e.at).toISOString()} — ${e.tool || 'action'}: ${e.decision.toUpperCase()}${e.reasons.length ? ` (${e.reasons.join(', ')})` : ''}`);
        return new Response(lines.join('\n'), { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });
      }
      return new Response('Not found', { status: 404 });
    },
  };
}

export { accountToken };
