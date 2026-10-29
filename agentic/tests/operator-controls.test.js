import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {newIdentity,createExecution,createIntent} from '../lib/authority.js';
import {fixture,AGENT,TOOL,RESOURCE,ACTION,ARGS} from '../lib/authority-fixture.js';
import {signApproval,verifyApprovals,encodeApprovals,decodeApprovals} from '../lib/approvals.js';
import {LocalSentinel} from '../lib/sentinel.js';
import {LocalBudget} from '../lib/budget.js';
import {ExecutionJournal} from '../lib/pilot-receipts.js';
import {DurableSyntheticStore,createDurableSyntheticBackend} from '../lib/pilot-backend.js';
import {createSecurePilotGateway} from '../lib/pilot-mcp.js';
const dir=t=>{const d=mkdtempSync(join(tmpdir(),'faraday-operator-')),resources=[];t.after(()=>{for(const resource of resources)resource.close();rmSync(d,{recursive:true,force:true});});return {d,resources};};
function approvals(){
 const a=newIdentity(),b=newIdentity(),scope={capability:'capability-1234567890123456789',agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS};
 const bundle=[signApproval({...scope,approver:'finance',privatePem:a.privatePem}),signApproval({...scope,approver:'security',privatePem:b.privatePem})];
 const keys={finance:{publicPem:a.publicPem,role:'finance'},security:{publicPem:b.publicPem,role:'security'}};
 return {a,b,bundle,scope,keys};
}
test('E18 two independent signatures and roles are required',()=>{
 const a=approvals();assert.equal(verifyApprovals({...a.scope,bundle:a.bundle,approverKeys:a.keys,quorum:2,requiredRoles:['finance','security']}).approved,true);
 assert.deepEqual(decodeApprovals(encodeApprovals(a.bundle)),a.bundle);
 assert.throws(()=>verifyApprovals({...a.scope,bundle:a.bundle.slice(0,1),approverKeys:a.keys,quorum:2}));
 assert.throws(()=>verifyApprovals({...a.scope,bundle:[a.bundle[0],a.bundle[0]],approverKeys:a.keys,quorum:2}));
});
test('E18 two approver aliases sharing a public key do not satisfy quorum',()=>{
 const a=approvals();
 const duplicate=signApproval({...a.scope,approver:'security',privatePem:a.a.privatePem});
 const keys={...a.keys,security:{publicPem:a.a.publicPem,role:'security'}};
 assert.throws(()=>verifyApprovals({...a.scope,bundle:[a.bundle[0],duplicate],approverKeys:keys,quorum:2,requiredRoles:['finance','security']}),/duplicate-approver-key/);
});
test('E18 consent cannot authorize another agent, resource, capability or arguments',()=>{
 const a=approvals();for(const change of [{agent:'bad'},{resource:'other'},{capability:a.scope.capability+'x'},{args:{...ARGS,amount_cents:1}}])
  assert.throws(()=>verifyApprovals({...a.scope,...change,bundle:a.bundle,approverKeys:a.keys,quorum:2}));
});
test('E18 forged signature and expiry are rejected',()=>{
 const a=approvals();assert.throws(()=>verifyApprovals({...a.scope,bundle:a.bundle,approverKeys:a.keys,quorum:2,now:Math.floor(Date.now()/1000)+500}));
 const fake=signApproval({...a.scope,approver:'finance',privatePem:newIdentity().privatePem});
 assert.throws(()=>verifyApprovals({...a.scope,bundle:[fake,a.bundle[1]],approverKeys:a.keys,quorum:2}));
});
test('E19 emergency stop persists across two SQLite connections',t=>{
 const {d,resources}=dir(t),path=join(d,'s.sqlite'),a=new LocalSentinel(path);resources.push(a);
 a.stop(true);const b=new LocalSentinel(path);resources.push(b);
 assert.equal(b.isBlocked('dummy'),true);b.stop(false);
 assert.equal(a.isBlocked('dummy'),false);assert.equal(a.verifyChain().verified,true);
});
test('E19 stop changes roll back when audit storage fails',t=>{
 const {d,resources}=dir(t),sentinel=new LocalSentinel(join(d,'s.sqlite'));resources.push(sentinel);
 sentinel.stop(true);
 sentinel.db.exec("CREATE TRIGGER reject_control BEFORE INSERT ON events WHEN NEW.kind='control' BEGIN SELECT RAISE(FAIL,'audit unavailable'); END");
 assert.throws(()=>sentinel.stop(false),/sentinel-storage-unavailable/);
 assert.equal(sentinel.isStopped(),true);assert.equal(sentinel.verifyChain().verified,true);
});
test('E19 denial quarantine and hash-chain mutation detection',t=>{
 const {d,resources}=dir(t),path=join(d,'s.sqlite');let now=10000;const a=new LocalSentinel(path,{threshold:2,now:()=>now,cooldownMs:1000});resources.push(a);
 a.record('deny','IP-1','invalid-proof');a.record('deny','IP-1','invalid-proof');
 assert.equal(a.isBlocked('IP-1'),true);assert.equal(a.isBlocked('IP-2'),false);now=12000;assert.equal(a.isBlocked('IP-1'),false);
 a.db.exec("UPDATE events SET reason='forged' WHERE seq=1");assert.equal(a.verifyChain().verified,false);
});
test('E17 budgets persist and fail closed for exhausted or unknown agents',t=>{
 const {d,resources}=dir(t),path=join(d,'q.sqlite'),limits={[AGENT]:{maxCalls:1,windowMs:60000}};
 const a=new LocalBudget(path,{limits});resources.push(a);assert.equal(a.consume(AGENT).remaining,0);
 const b=new LocalBudget(path,{limits});resources.push(b);assert.throws(()=>b.consume(AGENT),/budget-exhausted/);
 assert.throws(()=>b.consume('unknown'),/no-budget-policy/);
 assert.throws(()=>b.consume('constructor'),/no-budget-policy/);
});
test('E17 clock rollback cannot reopen an earlier unused window',t=>{
 const {d,resources}=dir(t),path=join(d,'q.sqlite'),limits={[AGENT]:{maxCalls:1,windowMs:60000}};let time=120000;
 const first=new LocalBudget(path,{limits,now:()=>time});resources.push(first);first.consume(AGENT);
 const second=new LocalBudget(path,{limits,now:()=>time});resources.push(second);
 time=60000;assert.throws(()=>second.consume(AGENT),/budget-clock-rollback/);
 time=180000;assert.equal(second.consume(AGENT).remaining,0);
});
async function listen(t,server){await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));return 'http://127.0.0.1:'+server.address().port;}
async function gatewaySetup(t){
 const {d:root,resources}=dir(t),f=fixture(root),receiptKey=newIdentity(),backendKey=newIdentity(),a=newIdentity(),b=newIdentity();
 const journal=new ExecutionJournal(join(root,'j.sqlite')),store=new DurableSyntheticStore(join(root,'b.sqlite'));
 const sentinel=new LocalSentinel(join(root,'s.sqlite'),{threshold:2}),budget=new LocalBudget(join(root,'q.sqlite'),{limits:{[AGENT]:{maxCalls:1,windowMs:60000}}});
 resources.push(f,journal,store,sentinel,budget);
 const backend=createDurableSyntheticBackend({secret:f.backendSecret,store,attestationPrivatePem:backendKey.privatePem});
 const bk=await listen(t,backend);
 const approvalConfig={approverKeys:{finance:{publicPem:a.publicPem,role:'finance'},security:{publicPem:b.publicPem,role:'security'}},quorum:2,requiredRoles:['finance','security']};
 const server=createSecurePilotGateway({gate:f.gate,journal,sentinel,budget,approvalConfig,receiptPrivatePem:receiptKey.privatePem,backendPublicPem:backendKey.publicPem,
 backendUrl:bk+'/internal/execute',backendSecret:f.backendSecret});
 const url=await listen(t,server);
 const bundle=(capability)=>[signApproval({capability,agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,approver:'finance',privatePem:a.privatePem}),
 signApproval({capability,agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,approver:'security',privatePem:b.privatePem})];
 async function call(capability=f.capability,proof=f.proof,withApproval=true){
  const body={jsonrpc:'2.0',id:1,method:'tools/call',params:{name:TOOL,arguments:ARGS,_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28'}}};
  const headers={'content-type':'application/json','mcp-protocol-version':'2026-07-28','mcp-method':'tools/call','mcp-name':TOOL,
   'x-faraday-capability':capability,'x-faraday-proof':Buffer.from(JSON.stringify(proof)).toString('base64url')};
  if(withApproval)headers['x-faraday-approvals']=encodeApprovals(bundle(capability));
  return (await fetch(url+'/mcp',{method:'POST',headers,body:JSON.stringify(body)})).status;
 }
 return {f,store,sentinel,call};
}
test('E18/E19/E17 integrated: no approval denied, signed consent executes, replay blocked',async t=>{
 const x=await gatewaySetup(t);
 assert.equal(await x.call(x.f.capability,x.f.proof,false),403);
 assert.equal(x.store.count(),0);
 assert.equal(await x.call(),200);
 assert.equal(x.store.count(),1);
 assert.equal(await x.call(),403);
});
test('E19 integrated: emergency stop blocks correctly approved operation before side effect',async t=>{
 const x=await gatewaySetup(t);x.sentinel.stop(true);
 assert.equal(await x.call(),403);assert.equal(x.store.count(),0);
 x.sentinel.stop(false);
 assert.equal(await x.call(),200);assert.equal(x.store.count(),1);
});
test('E17 integrated: second signed capability cannot exceed fixed call budget',async t=>{
 const x=await gatewaySetup(t);assert.equal(await x.call(),200);
 const intent=createIntent({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,agentPrivatePem:x.f.agent.privatePem});
 const second=x.f.iss.issue(intent);
 const proof=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,capability:second,agentPrivatePem:x.f.agent.privatePem});
 assert.equal(await x.call(second,proof),403);assert.equal(x.store.count(),1);
});
