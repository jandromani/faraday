import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,symlinkSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {captureSynthetic,syntheticFixture,verifyTrace,replaySynthetic,diffSynthetic,readSyntheticTrace,readReplayPolicy} from '../lib/timemachine.js';

function temp(t){const d=mkdtempSync(join(tmpdir(),'faraday-time-test-'));t.after(()=>rmSync(d,{recursive:true,force:true}));return d;}
test('E21 deterministic trace for same synthetic seed',()=>{
  const x=captureSynthetic({seed:42}),y=captureSynthetic({seed:42});assert.deepEqual(x,y);
  assert.equal(x.steps.length,15);assert.equal(verifyTrace(x).verified,true);
  assert.equal(replaySynthetic(x).summary.divergences,0);
});
test('E21 permitted synthetic write is applied once; second intent is a duplicate',()=>{
  const x=captureSynthetic();assert.equal(x.steps.at(-3).outcome,'applied');assert.equal(x.steps.at(-2).outcome,'duplicate');
  assert.equal(x.steps.at(-1).outcome,'denied');
});
test('E21 policy restriction changes trace without performing a tool call',()=>{
  const x=captureSynthetic(),stricter={allow:x.policy.allow.filter(r=>r.agent!=='finance')};
  const result=replaySynthetic(x,{policy:stricter});assert.ok(result.summary.divergences>0);
  assert.ok(result.divergences.some(y=>y.was==='applied'&&y.now==='denied'));
  assert.equal(result.mode,'offline-no-effects');
});
test('E21 explicitly invalid replay policies are rejected instead of using the original',()=>{
  const trace=captureSynthetic();
  for(const policy of [null,false,0,''])assert.throws(()=>replaySynthetic(trace,{policy}),/Invalid TimeMachine object/);
  assert.equal(replaySynthetic(trace).summary.divergences,0);
});
test('E21 corrupted recorded outcome rejects even with a recomputed but inconsistent claim',()=>{
  const x=captureSynthetic();x.steps[0].outcome='applied';assert.throws(()=>verifyTrace(x),/chain corruption/);
});
test('E21 chain detects mutation of operation IDs and root hash',()=>{
  const x=captureSynthetic();x.steps[1].intent.id='changed';assert.throws(()=>verifyTrace(x),/chain corruption/);
  const y=captureSynthetic();y.rootHash='a'.repeat(64);assert.throws(()=>verifyTrace(y),/root mismatch/);
});
test('E21 synthetic trace diff reports seed and policy differences',()=>{
  const a=captureSynthetic({seed:42}),b=captureSynthetic({seed:43});const d=diffSynthetic(a,b);
  assert.equal(d.format,'faraday-timemachine-diff');assert.ok(d.summary.changed>0);
});
test('E21 policies have exact role/tool/resource/action scopes with validation',()=>{
  const f=syntheticFixture();assert.throws(()=>captureSynthetic({policy:{allow:[{agent:'*',tool:'read_document',resource:'doc:demo',op:'read'}]},intents:f.intents}),/Invalid replay rule/);
  assert.throws(()=>captureSynthetic({policy:{allow:[]},intents:[{id:'x',agent:'a',tool:'t',resource:'r',op:'read',key:'k',value:100}]}),/Read intent/);
  assert.throws(()=>captureSynthetic({seed:-1}),/Invalid synthetic seed/);
});
test('E21 rejects partial custom inputs instead of silently replaying the fixture',()=>{
  const fixture=syntheticFixture();
  assert.throws(()=>captureSynthetic({policy:fixture.policy}),/must be provided together/);
  assert.throws(()=>captureSynthetic({intents:fixture.intents}),/must be provided together/);
  assert.throws(()=>captureSynthetic({seed:-1,policy:fixture.policy,intents:fixture.intents}),/Invalid synthetic seed/);
  assert.equal(captureSynthetic({policy:{allow:[]},intents:[]}).steps.length,0);
});
test('E21 detects conflicting repeated operation IDs',()=>{
  const f=syntheticFixture();f.intents.push({...f.intents.at(-3),value:1,id:'fixture-20'});
  const x=captureSynthetic({policy:f.policy,intents:f.intents});assert.equal(x.steps.at(-1).outcome,'idempotency-conflict');
});
test('E21 local files accept only expected schemas',t=>{
  const d=temp(t),p=join(d,'trace.json'),policy=join(d,'policy.json');
  const x=captureSynthetic();writeFileSync(p,JSON.stringify(x));
  assert.equal(readSyntheticTrace(p).rootHash,x.rootHash);
  writeFileSync(policy,JSON.stringify(x.policy));assert.equal(readReplayPolicy(policy).allow.length,4);
  writeFileSync(policy,JSON.stringify({...x.policy,evil:true}));assert.throws(()=>readReplayPolicy(policy),/Invalid TimeMachine object/);
});
test('E21 local files reject symlinks',t=>{
  const d=temp(t),p=join(d,'trace.json'),link=join(d,'link.json');
  writeFileSync(p,JSON.stringify(captureSynthetic()));
  try{symlinkSync(p,link);}catch(error){if(process.platform==='win32'&&error.code==='EPERM'){t.skip('Windows account cannot create symbolic links');return;}throw error;}
  assert.throws(()=>readSyntheticTrace(link),/Unsafe trace file/);
});
test('E21 actual replay never invokes network or filesystem effectors',()=>{
  const original=globalThis.fetch;
  globalThis.fetch=()=>{throw Error('network access must not occur');};
  try{const r=replaySynthetic(captureSynthetic());assert.equal(r.summary.divergences,0);}finally{globalThis.fetch=original;}
});

test('E21 metadata hash detects policy expansion and edited limitations',()=>{
  const x=captureSynthetic();x.policy.allow.push({agent:'adversary',tool:'pay_invoice',resource:'invoice:demo',op:'write'});
  assert.throws(()=>verifyTrace(x),/metadata corruption/);
  const y=captureSynthetic();y.limitations.push('incorrect assurance');assert.throws(()=>verifyTrace(y),/metadata corruption/);
});
