import { classify, observationForTelemetry } from './shield.mjs';

export const INSPECTION_SCHEMA = 'protect-me/shield-inspection@v1';

// Internal service-binding RPC only. Never accept a raw Request, IP, body,
// query string, cookies, or client-supplied bot-verification headers.
export async function inspectCrawlerRequest(input, secret) {
  if (!input || typeof input !== 'object' ||
      !['GET', 'HEAD'].includes(input.method) ||
      typeof input.pathname !== 'string' || !input.pathname.startsWith('/') ||
      input.pathname.length > 512 || input.pathname.includes('?') ||
      typeof input.userAgent !== 'string' || input.userAgent.length > 256 ||
      typeof input.verifiedBot !== 'boolean' ||
      (input.botScore != null && (!Number.isFinite(input.botScore) || input.botScore < 0 || input.botScore > 100)) ||
      (input.asn != null && (!Number.isSafeInteger(input.asn) || input.asn < 0)) ||
      (input.country != null && (typeof input.country !== 'string' || !/^[A-Z]{2}$/.test(input.country)))) {
    throw new TypeError('SHIELD_INSPECTION_INPUT_INVALID');
  }
  if (typeof secret !== 'string' || !secret) {
    return { schema: INSPECTION_SCHEMA, action: 'unverified', verdict: 'NO_SIGNING_KEY', receipt: null, receiptKind: 'none' };
  }
  const cf = {
    botManagement: { verifiedBot: input.verifiedBot, ...(input.botScore != null ? { score: input.botScore } : {}) },
    ...(input.asn != null ? { asn: input.asn } : {}),
    ...(input.country != null ? { country: input.country } : {}),
  };
  const observed = await classify({
    method: input.method,
    url: `https://inspection.invalid${input.pathname}`,
    userAgent: input.userAgent,
    cf,
  }, { service: 'founder-control-room' }, secret);
  if (observed.event.verdict === 'CLASSIFY_ERROR') {
    return { schema: INSPECTION_SCHEMA, action: 'unverified', verdict: 'CLASSIFY_ERROR', receipt: null, receiptKind: 'none' };
  }
  const evidence = await observationForTelemetry(observed, secret);
  return {
    schema: INSPECTION_SCHEMA,
    action: observed.event.verdict === 'PROBE' ? 'deny' : 'pass',
    verdict: observed.event.verdict,
    receipt: evidence.receipt,
    receiptKind: evidence.receiptKind,
    evidence,
  };
}
