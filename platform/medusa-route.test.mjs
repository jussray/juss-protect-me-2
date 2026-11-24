import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFounderRoom } from './founder-room.mjs';
const room=createFounderRoom();
const url='https://example.invalid/founder/medusa';
const env={FOUNDER_EMAIL:'fictional@example.invalid',FOUNDER_PASSWORD:'synthetic-test-only',FOUNDER_SALT:'0102030405060708',FOUNDER_ITERS:'1000',SESSION_SECRET:'test-only-session-secret'};
test('medusa route denies unauthenticated requests and malformed cookies',async()=>{
  for (const cookie of ['', 'pf_session=%ZZ']) {
    for(const method of ['GET','POST']) {
      const r=await room.fetch(new Request(url,{method,headers:{cookie}}),env);
      assert.equal(r.status,302);assert.equal(r.headers.get('location'),'/founder');
    }
  }
});
test('synthetic founder login reaches review form',async()=>{
  const login=await room.fetch(new Request('https://example.invalid/founder/login',{method:'POST',body:new URLSearchParams({email:env.FOUNDER_EMAIL,password:env.FOUNDER_PASSWORD})}),env);
  assert.equal(login.status,302);
  const cookie=login.headers.get('set-cookie').split(';')[0];
  const r=await room.fetch(new Request(url,{headers:{cookie}}),env);
  assert.equal(r.status,200);assert.match(await r.text(),/Evidence review/);
});
