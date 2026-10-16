// Protect Me Shield — edge defense for Cloudflare Workers (and Node via adapter).
//
// Order of operations for every request:
//   1. rate limit dynamic paths (fail closed if the limiter binding is missing)
//   2. classify the request (human / automation / claimed crawler / verified bot / probe)
//   3. emit one telemetry line for anything that is not plain traffic
//   4. answer known scanner probes with an inert decoy 404 (no app code runs)
//   5. otherwise hand the request to your upstream Worker unchanged
//
// Hard boundaries: owned surfaces only. No retaliation, no outbound calls, no real
// data in decoys. The decoy is a static JSON 404.

export const DEFAULT_PROBE_PATHS = Object.freeze([
  '/.env', '/.git', '/.aws', '/.ssh', '/.svn', '/.DS_Store', '/wp-admin', '/wp-login.php',
  '/xmlrpc.php', '/phpmyadmin', '/server-status', '/etc/passwd', '/vendor/phpunit', '/actuator',
  '/cgi-bin', '/config.json', '/.vscode',
]);

export const DEFAULT_AUTOMATION_PATTERN =
  /(bot|crawler|spider|scanner|headless|curl|wget|python-requests|go-http-client|httpclient|zgrab|sqlmap|nikto|masscan|nmap|nuclei)/i;

export const DEFAULT_CRAWLER_CLAIMS = Object.freeze([
  ['googlebot', /googlebot/i], ['bingbot', /bingbot/i], ['applebot', /applebot/i],
  ['gptbot', /gptbot/i], ['chatgpt-user', /chatgpt-user/i], ['claudebot', /claudebot/i],
]);

export const DEFAULTS = Object.freeze({
  service: 'app',
  rateLimit: Object.freeze({
    binding: 'SHIELD_RATE_LIMITER',
    paths: Object.freeze(['/api', '/api/*']),
    retryAfterSeconds: 60,
  }),
  probePaths: DEFAULT_PROBE_PATHS,
  automationPattern: DEFAULT_AUTOMATION_PATTERN,
  crawlerClaims: DEFAULT_CRAWLER_CLAIMS,
  secretEnv: 'SHIELD_SECRET',
  blockTraceAndConnect: true,
  telemetry: true,
});

const isPathList = (v) => Array.isArray(v) && v.every((x) => typeof x === 'string' && x.startsWith('/'));

export function resolveConfig(config = {}) {
  const cfg = Object.freeze({
    ...DEFAULTS,
    ...config,
    rateLimit: Object.freeze({ ...DEFAULTS.rateLimit, ...(config.rateLimit ?? {}) }),
  });
  // Fail at startup, not on every request, when the config is malformed.
  if (!isPathList(cfg.rateLimit.paths)) throw new TypeError('shield config: rateLimit.paths must be an array of paths starting with "/"');
  if (!isPathList(cfg.probePaths)) throw new TypeError('shield config: probePaths must be an array of paths starting with "/"');
  if (!(Number.isInteger(cfg.rateLimit.retryAfterSeconds) && cfg.rateLimit.retryAfterSeconds > 0)) {
    throw new TypeError('shield config: rateLimit.retryAfterSeconds must be a positive integer');
  }
  if (typeof cfg.rateLimit.binding !== 'string' || !cfg.rateLimit.binding) throw new TypeError('shield config: rateLimit.binding must be a name');
  return cfg;
}

/**
 * The path as a permissive router would see it: percent-decoded (repeatedly, so
 * %2561 cannot hide "a"), duplicate slashes collapsed, lower-cased. Matching on
 * this means "/%61pi", "/API" and "//api" cannot dodge a rule for "/api".
 * Over-matching only ever makes the Shield stricter.
 */
export function canonicalPath(pathname) {
  let p = String(pathname ?? '/');
  for (let i = 0; i < 3; i += 1) {
    let next;
    try { next = decodeURIComponent(p); } catch { break; }
    if (next === p) break;
    p = next;
  }
  p = p.replace(/\\/g, '/').replace(/\/{2,}/g, '/').toLowerCase();
  return p.startsWith('/') ? p : `/${p}`;
}

// "/api" matches exactly; "/api/*" matches anything below /api/. Case-insensitive, on the canonical path.
export function matchPath(pathname, patterns) {
  const path = canonicalPath(pathname);
  return patterns.some((raw) => {
    const pat = raw.toLowerCase();
    return pat.endsWith('/*') ? path.startsWith(pat.slice(0, -1)) : path === pat || path === `${pat}/`;
  });
}

// Prefix match on the canonical path; dot-entries like "/.env" or "/.git" also match
// that segment anywhere ("/backup/.git/config") and its variants (".env.local").
export function isProbePath(pathname, probePaths = DEFAULT_PROBE_PATHS) {
  const path = canonicalPath(pathname);
  const segments = path.split('/');
  return probePaths.some((raw) => {
    const c = raw.toLowerCase();
    if (path === c || path.startsWith(`${c}/`)) return true;
    const name = c.slice(1);
    return c.startsWith('/.') && !name.includes('/')
      && segments.some((seg) => seg === name || seg.startsWith(`${name}.`));
  });
}

function clean(value, max = 256) {
  // eslint-disable-next-line no-control-regex -- strip control chars from untrusted input before logging
  return String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((k) => [k, stable(value[k])]));
  }
  return value;
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

async function sha256(text) {
  return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
}

async function hmac(secret, text) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  return hex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(text)));
}

// Receipts are an HMAC of the canonical event when a secret is configured, so they
// cannot be forged by anyone who only sees logs. Without a secret they are a plain
// SHA-256 (integrity only, not authenticity), and the observation says so.
async function receiptFor(event, secret) {
  const material = JSON.stringify(stable(event));
  return secret ? { receipt: await hmac(secret, material), receiptKind: 'hmac-sha256' }
    : { receipt: await sha256(material), receiptKind: 'sha256-unauthenticated' };
}

export async function verifyReceipt(observation, secret) {
  if (!observation?.event || !observation?.receipt) return false;
  const { receipt } = await receiptFor(observation.event, secret);
  return receipt === observation.receipt;
}

/**
 * Classify one request. Pure apart from crypto; never throws.
 * @param {{method:string, url:string, userAgent?:string, sourceIp?:string|null, cf?:object}} input
 */
export async function classify(input, config = DEFAULTS, secret = null) {
  const cfg = config === DEFAULTS ? DEFAULTS : resolveConfig(config);
  try {
    const method = clean(input.method, 16).toUpperCase() || 'GET';
    const pathname = new URL(input.url ?? '/', 'http://local.invalid').pathname;
    const userAgent = clean(input.userAgent, 256);
    const cf = input.cf ?? {};
    const bm = cf.botManagement ?? cf.bot_management ?? {};
    const verifiedBot = bm.verifiedBot === true || bm.verified_bot === true;
    const botScore = Number.isFinite(Number(bm.score)) ? Number(bm.score) : null;
    const claimedCrawler = cfg.crawlerClaims.find(([, re]) => re.test(userAgent))?.[0] ?? null;
    const probe = isProbePath(pathname, cfg.probePaths)
      || (cfg.blockTraceAndConnect && (method === 'TRACE' || method === 'CONNECT'));
    const automated = verifiedBot || Boolean(claimedCrawler) || cfg.automationPattern.test(userAgent)
      || (botScore !== null && botScore < 10);
    const verdict = probe ? 'PROBE'
      : verifiedBot ? 'VERIFIED_BOT'
        : claimedCrawler ? 'CLAIMED_CRAWLER'
          : automated ? 'AUTOMATION'
            : 'NORMAL';
    const sourceIp = clean(input.sourceIp, 96) || null;
    const event = {
      schema: 'protect-me/shield-event@v1',
      service: cfg.service,
      method,
      pathname: clean(pathname, 512),
      verdict,
      identity: {
        // A stable pseudonymous actor id only when a server-held secret exists.
        // Raw IPs are never logged.
        actor: secret && sourceIp ? await hmac(secret, `ip:${sourceIp}`) : null,
        asn: Number.isFinite(Number(cf.asn)) ? Number(cf.asn) : null,
        country: clean(cf.country, 8) || null,
        userAgent: userAgent || null,
        claimedCrawler,
        verifiedBot,
        botScore,
      },
    };
    const checks = [
      { check: 'probe-path', result: probe ? 'DECOY' : 'PASS' },
      { check: 'identity-claim', result: claimedCrawler && !verifiedBot ? 'UNVERIFIED_CLAIM' : 'PASS' },
      { check: 'automation', result: automated ? (verifiedBot ? 'VERIFIED' : 'FLAGGED') : 'PASS' },
      { check: 'attribution', result: event.identity.actor ? 'PSEUDONYMOUS_ID' : 'UNKNOWN_ACTOR' },
    ];
    return Object.freeze({ event, checks, notable: verdict !== 'NORMAL', ...(await receiptFor(event, secret)) });
  } catch (error) {
    return Object.freeze({
      event: { schema: 'protect-me/shield-event@v1', service: cfg.service, verdict: 'CLASSIFY_ERROR', error: clean(error?.message, 160) },
      checks: [], notable: true, receipt: null, receiptKind: 'none',
    });
  }
}

function jsonResponse(status, body, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      ...extra,
    },
  });
}

export async function rateLimit(request, env, config = DEFAULTS) {
  const cfg = config === DEFAULTS ? DEFAULTS : resolveConfig(config);
  const { pathname } = new URL(request.url);
  if (!matchPath(pathname, cfg.rateLimit.paths)) return null;
  const limiter = env?.[cfg.rateLimit.binding];
  if (!limiter || typeof limiter.limit !== 'function') {
    return jsonResponse(503, { ok: false, error: 'rate_limit_unavailable' });
  }
  // Only Cloudflare's own header is trusted. A missing edge identity shares one
  // fail-safe bucket instead of letting the client pick its own key.
  const ip = clean(request.headers.get('cf-connecting-ip'), 96);
  let outcome;
  try {
    outcome = await limiter.limit({ key: ip ? `ip:${ip}` : 'ip:unknown' });
  } catch {
    outcome = null;
  }
  if (!outcome || typeof outcome.success !== 'boolean') {
    // A limiter that throws or answers nonsense fails closed, same as a missing one.
    return jsonResponse(503, { ok: false, error: 'rate_limit_unavailable' });
  }
  if (outcome.success) return null;
  return jsonResponse(429, { ok: false, error: 'rate_limit_exceeded' },
    { 'retry-after': String(cfg.rateLimit.retryAfterSeconds) });
}

/**
 * Diagnostic logs must not include attacker-controlled URL paths or User-Agent
 * strings. Preserve a separately signed evidence-only receipt for the sanitized
 * event so logging cannot silently upgrade an untrusted claim to authority.
 */
export async function observationForTelemetry(observation, secret = null) {
  const event = observation?.event ?? {};
  const identity = event.identity ?? {};
  const sanitized = {
    schema: 'protect-me/shield-event@v1',
    service: String(event.service ?? 'unknown'),
    method: /^[A-Z]{1,12}$/.test(event.method ?? '') ? event.method : 'OTHER',
    pathname: '[redacted]',
    verdict: event.verdict ?? 'CLASSIFY_ERROR',
    identity: {
      actor: identity.actor ?? null,
      asn: identity.asn ?? null,
      country: identity.country ?? null,
      userAgent: null,
      claimedCrawler: identity.claimedCrawler ?? null,
      verifiedBot: identity.verifiedBot === true,
      botScore: identity.botScore ?? null,
    },
  };
  return Object.freeze({
    event: sanitized,
    checks: observation?.checks ?? [],
    notable: observation?.notable === true,
    ...(await receiptFor(sanitized, secret)),
  });
}

export function decoyResponse() {
  return jsonResponse(404, { error: 'not_found' });
}

/**
 * Wrap a Worker. Usage:
 *   import app from './app.js';
 *   export default createShield(app, { service: 'my-app', rateLimit: { paths: ['/api', '/api/*'] } });
 */
export function createShield(upstream, config = {}) {
  const cfg = resolveConfig(config);
  if (!upstream || typeof upstream.fetch !== 'function') {
    throw new Error('createShield: upstream must be a Worker with a fetch() handler');
  }
  return {
    ...upstream,
    async fetch(request, env, ctx) {
      const limited = await rateLimit(request, env, cfg);
      if (limited) return limited;
      const secret = clean(env?.[cfg.secretEnv], 4096) || null;
      const observation = await classify({
        method: request.method,
        url: request.url,
        userAgent: request.headers.get('user-agent'),
        sourceIp: request.headers.get('cf-connecting-ip'),
        cf: request.cf,
      }, cfg, secret);
      if (cfg.telemetry && observation.notable) {
        const line = observationForTelemetry(observation, secret)
          .then((safe) => console.log('[protect-me-shield]', JSON.stringify(safe)))
          .catch(() => console.log('[protect-me-shield]', '{"event":{"verdict":"TELEMETRY_ERROR"}}'));
        if (ctx?.waitUntil) ctx.waitUntil(line);
      }
      if (observation.event.verdict === 'PROBE') return decoyResponse();
      return upstream.fetch.call(upstream, request, env, ctx);
    },
  };
}

/**
 * Node adapter input. Forwarding headers are client-controlled, so they are used
 * only when you set trustProxy: true behind a proxy you control.
 */
export function nodeRequestInput(req, { trustProxy = false } = {}) {
  const h = req?.headers ?? {};
  const first = (v) => (Array.isArray(v) ? v[0] : v);
  const forwarded = trustProxy ? String(first(h['cf-connecting-ip']) ?? first(h['x-forwarded-for']) ?? '').split(',')[0] : '';
  return {
    method: req?.method,
    url: req?.url,
    userAgent: first(h['user-agent']),
    sourceIp: clean(forwarded, 96) || clean(req?.socket?.remoteAddress, 96) || null,
  };
}
