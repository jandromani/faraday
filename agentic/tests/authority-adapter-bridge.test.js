import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fixture,AGENT,TOOL,RESOURCE,ACTION,ARGS} from '../lib/authority-fixture.js';
import {createAuthorityMediatedAdapter} from '../lib/authority-adapter-bridge.js';
const contract=()=>({version:1,framework:'langgraph',adapter:'accounting',mode:'observe-only',
 capabilities:[{tool:TOOL,operation:ACTION,resource:RESOURCE}]});
const request=f=>({tool:TOOL,operation:ACTION,resource:RESOURCE,capability:f.capability,proof:f.proof});
function setup(t){
 const dir=mkdtempSync(join(tmpdir(),'faraday-authority-adapter-'));
 const f=fixture(dir,{now:1_800_000_000});
 t.after(()=>{f.close();rmSync(dir,{recursive:true,force:true});});
 return f;
}
test('R4 exact-scope adapter invokes real cryptographic AuthorityGate, once',async t=>{
 const f=setup(t);let calls=0;const events=[];
 const adapter=createAuthorityMediatedAdapter({contract:contract(),gate:f.gate,
  dispatch:async decision=>{calls++;assert.equal(decision.agent,AGENT);assert.equal(decision.tool,TOOL);
   assert.equal(decision.action,ACTION);assert.deepEqual(decision.args,ARGS);return {ok:true,operationId:decision.operationId};},
  onDecision:meta=>events.push(meta)});
 const r=await adapter.invoke(request(f));
 assert.equal(r.ok,true);assert.equal(calls,1);
 assert.equal(events.length,1);assert.equal(events[0].status,'authorized');
 assert.ok(!JSON.stringify(events).includes('supplier_demo'));
 await assert.rejects(adapter.invoke(request(f)),/capability-replayed/);assert.equal(calls,1);
});
test('R4 undeclared or substituted operations cannot reach backend',async t=>{
 const f=setup(t);let calls=0;
 const adapter=createAuthorityMediatedAdapter({contract:contract(),gate:f.gate,dispatch:()=>{calls++;}});
 await assert.rejects(adapter.invoke({...request(f),operation:'write'}),/not-declared/);
 await assert.rejects(adapter.invoke({...request(f),resource:'invoice:other'}),/not-declared/);
 assert.equal(calls,0);
 // Blocked metadata cannot consume genuine Authority capability.
 assert.equal((await adapter.invoke(request(f))),undefined);assert.equal(calls,1);
});
test('R4 rejects revoked identity and fails closed when audit storage fails',async t=>{
 const f=setup(t);let called=0;f.gatewayLedger.revoke('agent',AGENT);
 const blocked=createAuthorityMediatedAdapter({contract:contract(),gate:f.gate,dispatch:()=>{called++;}});
 await assert.rejects(blocked.invoke(request(f)),/authority-revoked/);assert.equal(called,0);
 const other=setup(t);
 const unavailable=createAuthorityMediatedAdapter({contract:contract(),gate:other.gate,dispatch:()=>{called++;},
  onDecision:()=>{throw Error('audit-storage-unavailable');}});
 await assert.rejects(unavailable.invoke(request(other)),/audit-storage-unavailable/);
 assert.equal(called,0);
});
