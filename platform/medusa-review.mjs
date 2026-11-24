// Read-only evidence review. No target execution, fetching, persistence or authorization.
const enc = new TextEncoder();
const MAX_BODY = 100000;
const MAX_SOURCE = 16384;
const MAX_QUOTE = 1024;
const headers = {'content-type':'text/html; charset=utf-8','cache-control':'no-store','referrer-policy':'no-referrer','x-content-type-options':'nosniff'};
export async function assessEvidence({source,expected,quote} = {}) {
  const base = {can_authorize:false,independent_truth_verified:false};
  if (typeof source !== 'string' || !source || enc.encode(source).length > MAX_SOURCE || typeof expected !== 'string' || !/^[0-9a-f]{64}$/i.test(expected) || typeof quote !== 'string' || quote.trim().length < 12 || enc.encode(quote).length > MAX_QUOTE) return {...base,status:'INVALID'};
  const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(source))), b=>b.toString(16).padStart(2,'0')).join('');
  const hash_matches = hash === expected.toLowerCase(), quote_matches = source.includes(quote);
  return {...base,status:hash_matches&&quote_matches?'MATCH':'MISMATCH',hash,hash_matches,quote_matches};
}
function page(result) {
  const findings = result ? `<section><h2>${result.status}</h2>${result.hash ? `<p>SHA-256: <code>${result.hash}</code></p><p>Hash match: ${result.hash_matches?'yes':'no'} · Quotation match: ${result.quote_matches?'yes':'no'}</p>`:''}<p>No independent truth verification or execution authority.</p></section>`:'';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Medusa evidence review</title><style>body{max-width:760px;margin:3rem auto;padding:0 1rem;background:#10131e;color:#eee;font:1rem/1.6 system-ui}label{display:block;margin-top:1rem}textarea,input{box-sizing:border-box;width:100%;background:#202537;color:white;border:1px solid #69748b;padding:.75rem}button{margin:1rem 0;padding:.8rem 1.2rem;background:#eacb88;color:#15151a;border:0}a{color:#eacb88}section{border:1px solid #69748b;padding:1rem}code{overflow-wrap:anywhere}</style></head><body><a href="/founder/room">Founder room</a><h1>Evidence review</h1><p>Compare submitted UTF-8 text and an exact quotation against an expected SHA-256. Submit only material you are authorized to review; do not submit secrets. This check does not prove source authenticity or authorize actions. No application-level persistence.</p>${findings}<form method="post" action="/founder/medusa"><label for="source">Evidence text</label><textarea id="source" name="source" rows="8" maxlength="16384" required></textarea><label for="expected">Expected SHA-256 of submitted text</label><input id="expected" name="expected" pattern="[0-9A-Fa-f]{64}" required><label for="quote">Exact quotation (at least 12 characters)</label><textarea id="quote" name="quote" rows="3" minlength="12" maxlength="1024" required></textarea><button>Review evidence</button></form></body></html>`;
}
function reply(message,status) { return new Response(message,{status,headers}); }
export async function handleMedusaReview(request) {
  if (request.method === 'GET') return reply(page(),200);
  if (request.method !== 'POST') return reply('Method not allowed',405);
  if (request.headers.get('origin') !== new URL(request.url).origin) return reply('Forbidden',403);
  if ((request.headers.get('content-type')||'').split(';')[0].trim().toLowerCase()!=='application/x-www-form-urlencoded') return reply('Unsupported content type',415);
  if (Number(request.headers.get('content-length')) > MAX_BODY) return reply('Request too large',413);
  if (!request.body) return reply('Missing input',400);
  const reader = request.body.getReader();
  let size=0, text=''; const decoder=new TextDecoder('utf-8',{fatal:true});
  try {
    while (true) { const {done,value}=await reader.read(); if(done) break; size+=value.byteLength; if(size>MAX_BODY){await reader.cancel();return reply('Request too large',413);} text+=decoder.decode(value,{stream:true}); }
    text+=decoder.decode();
  } catch { return reply('Malformed input',400); } finally { reader.releaseLock(); }
  const fields=new URLSearchParams(text);
  const names=['source','expected','quote'];
  if([...fields.keys()].length!==3 || names.some(n=>fields.getAll(n).length!==1)) return reply('Invalid fields',400);
  const result=await assessEvidence(Object.fromEntries(fields));
  return reply(page(result),result.status==='INVALID'?400:200);
}
