import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessEvidence, handleMedusaReview } from './medusa-review.mjs';
const source = 'This is a fictional evidence document.';
const sha = Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(source))).toString('hex');
const url = 'https://example.invalid/founder/medusa';
function submit(data, origin='https://example.invalid') {
  return new Request(url,{method:'POST',headers:{origin,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(data)});
}
test('exact submitted text and quotation yield evidence-only match',async()=>{
  const r=await assessEvidence({source,expected:sha,quote:'fictional evidence'});
  assert.equal(r.status,'MATCH'); assert.equal(r.can_authorize,false); assert.equal(r.independent_truth_verified,false);
});
test('changed text or absent quote fails',async()=>{
  assert.equal((await assessEvidence({source:source+'!',expected:sha,quote:'fictional evidence'})).status,'MISMATCH');
  assert.equal((await assessEvidence({source,expected:sha,quote:'not in this document'})).status,'MISMATCH');
});
test('invalid and short inputs are rejected',async()=>{
  for(const data of [{source,expected:'bad',quote:'fictional evidence'},{source,expected:sha,quote:'short'},{source:'x'.repeat(16385),expected:sha,quote:'fictional evidence'}]) assert.equal((await assessEvidence(data)).status,'INVALID');
});
test('GET serves read-only form',async()=>{
  const r=await handleMedusaReview(new Request(url)); assert.equal(r.status,200); assert.match(await r.text(),/Evidence review/); assert.equal(r.headers.get('cache-control'),'no-store');
});
test('POST returns result without echoing submitted material',async()=>{
  const r=await handleMedusaReview(submit({source,expected:sha,quote:'fictional evidence'})); const body=await r.text(); assert.equal(r.status,200); assert.match(body,/MATCH/); assert.ok(!body.includes(source)); assert.ok(!body.includes('fictional evidence')); assert.equal(r.headers.get('cache-control'),'no-store');
});
test('cross-origin, duplicate fields and oversized forms rejected',async()=>{
  assert.equal((await handleMedusaReview(submit({source,expected:sha,quote:'fictional evidence'},'https://other.invalid'))).status,403);
  assert.equal((await handleMedusaReview(submit([['source',source],['source',source],['expected',sha],['quote','fictional evidence']]))).status,400);
  assert.equal((await handleMedusaReview(submit({source:'x'.repeat(110000),expected:sha,quote:'fictional evidence'}))).status,413);
});
