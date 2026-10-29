import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fixture,AGENT,ARGS,TOOL,RESOURCE,ACTION} from '../lib/authority-fixture.js';
import {createExecution,newIdentity,AuthorityError,digest} from '../lib/authority.js';
import {ExecutionJournal,signReceipt,verifyReceipt} from '../lib/pilot-receipts.js';
import {DurableSyntheticStore,createDurableSyntheticBackend} from '../lib/pilot-backend.js';
import {createSecurePilotGateway} from '../lib/pilot-mcp.js';
import {signApproval,encodeApprovals} from '../lib/approvals.js';

const VERSION='2026-07-28';
function setup(t){
  const root=mkdtempSync(join(tmpdir(),'faraday-095-'));
  const f=fixture(root);
  const receiptKey=newIdentity(),backendKey=newIdentity();
  const journal=new ExecutionJournal(join(root,'journal.sqlite'));
  const store=new DurableSyntheticStore(join(root,'backend.sqlite'));
  const additional=[];
  t.after(()=>{for(const item of additional)item.close();f.close();journal.close();store.close();rmSync(root,{recursive:true,force:true});});
  return {root,f,receiptKey,backendKey,journal,store,additional};
}
const rpc=(method,params={},id=9)=>({jsonrpc:'2.0',id,method,params:{...params,_meta:{'io.modelcontextprotocol/protocolVersion':VERSION}}});
async function listen(t,server){await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));return `http://127.0.0.1:${server.address().port}`;}
async function post(url,body,{capability,proof,headers={}}={}){
  const auth=capability?{'x-faraday-capability':capability,'x-faraday-proof':Buffer.from(JSON.stringify(proof)).toString('base64url')}:{};
  const res=await fetch(url+'/mcp',{method:'POST',headers:{'content-type':'application/json','mcp-protocol-version':VERSION,'mcp-method':body.method,...(body.method==='tools/call'?{'mcp-name':body.params?.name}:{}),...auth,...headers},body:JSON.stringify(body)});
  return {status:res.status,json:await res.json()};
}
async function system(t,options={}){
  const env=setup(t);
  const backend=createDurableSyntheticBackend({secret:env.f.backendSecret,store:env.store,attestationPrivatePem:env.backendKey.privatePem});const backendUrl=await listen(t,backend);
  const gateway=createSecurePilotGateway({gate:env.f.gate,backendUrl:backendUrl+'/internal/execute',backendSecret:env.f.backendSecret,
    journal:env.journal,receiptPrivatePem:env.receiptKey.privatePem,backendPublicPem:env.backendKey.publicPem,...options});const url=await listen(t,gateway);
  return {...env,url,backendUrl};
}
const call=(args=ARGS)=>rpc('tools/call',{name:'pay_invoice',arguments:args});

test('backend credential requires HTTPS outside loopback unless explicitly opted in',t=>{
  const x=setup(t),options={gate:x.f.gate,backendSecret:x.f.backendSecret,journal:x.journal,receiptPrivatePem:x.receiptKey.privatePem,backendPublicPem:x.backendKey.publicPem};
  assert.throws(()=>createSecurePilotGateway({...options,backendUrl:'http://backend.example/internal/execute'}),/requires HTTPS/);
  assert.throws(()=>createSecurePilotGateway({...options,backendUrl:'http://backend.example/internal/execute',allowInsecureBackend:'true'}),/requires HTTPS/);
  assert.doesNotThrow(()=>createSecurePilotGateway({...options,backendUrl:'https://backend.example/internal/execute'}));
  assert.doesNotThrow(()=>createSecurePilotGateway({...options,backendUrl:'http://backend/internal/execute',allowInsecureBackend:true}));
});

test('signed MCP operation succeeds and receipt is independently verified',async t=>{
  const x=await system(t);const r=await post(x.url,call(),x.f);
  assert.equal(r.status,200);assert.equal(r.json.result.structuredContent.status,'simulated');
  const receipt=r.json.result.structuredContent.receipt;
  assert.deepEqual(verifyReceipt({publicPem:x.receiptKey.publicPem,receipt,backendPublicPem:x.backendKey.publicPem}).backendVerified,true);
  assert.equal(x.store.count(),1);assert.equal(x.journal.get(receipt.claims.operationId).state,'simulated');
  assert.ok(!JSON.stringify(receipt).includes('supplier_demo'));
});
test('stolen capability without agent signing key is denied',async t=>{
  const x=await system(t);const rogue=newIdentity();const fake=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,capability:x.f.capability,agentPrivatePem:rogue.privatePem});
  assert.equal((await post(x.url,call(),{capability:x.f.capability,proof:fake})).status,403);assert.equal(x.store.count(),0);
  assert.equal((await post(x.url,call(),x.f)).status,200);
});
test('capability replay denied after successful action',async t=>{
  const x=await system(t);assert.equal((await post(x.url,call(),x.f)).status,200);
  assert.equal((await post(x.url,call(),x.f)).status,403);assert.equal(x.store.count(),1);
});
test('argument tampering denied before side effect',async t=>{
  const x=await system(t);const changed={...ARGS,amount_cents:12000};
  assert.equal((await post(x.url,call(changed),x.f)).status,403);assert.equal(x.store.count(),0);
});
test('external policy is an additional filter and receives no raw identity or arguments',async t=>{
  let observed;
  const x=await system(t,{externalPolicy:{authorize:snapshot=>(observed=snapshot,{decision:'allow'})}});
  const rogue=newIdentity();const fake=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,capability:x.f.capability,agentPrivatePem:rogue.privatePem});
  assert.equal((await post(x.url,call(),{capability:x.f.capability,proof:fake})).status,403);
  assert.equal(x.store.count(),0);
  assert.equal((await post(x.url,call(),x.f)).status,200);
  assert.equal(x.store.count(),1);
  assert.doesNotMatch(JSON.stringify(observed),/supplier_demo|invoice:demo|dummy|amount_cents/);
});
test('external policy denial, invalid verdict and timeout prevent execution without spending capability',async t=>{
  let mode='deny';
  const x=await system(t,{externalPolicy:{timeoutMs:10,authorize:()=>mode==='timeout'?new Promise(()=>{}):mode==='invalid'?{allowed:true}:{decision:mode}}});
  for(const value of ['deny','invalid','timeout']){mode=value;assert.equal((await post(x.url,call(),x.f)).status,403);assert.equal(x.store.count(),0);}
  mode='allow';assert.equal((await post(x.url,call(),x.f)).status,200);assert.equal(x.store.count(),1);
});
test('issuer key revocation during external policy wait prevents execution',async t=>{
  let release,started;
  const pending=new Promise(resolve=>{started=resolve;});
  const x=await system(t,{externalPolicy:{authorize:()=>{started();return new Promise(resolve=>{release=resolve;});}}});
  const request=post(x.url,call(),x.f);await pending;
  for(const key of Object.keys(x.f.gate.keys))delete x.f.gate.keys[key];
  release({decision:'allow'});
  assert.equal((await request).status,403);assert.equal(x.store.count(),0);
});
test('policy revocation during external policy wait prevents execution without spending capability',async t=>{
  let release,started,first=true;
  const pending=new Promise(resolve=>{started=resolve;});
  const x=await system(t,{externalPolicy:{authorize:()=>{if(!first)return {decision:'allow'};first=false;started();return new Promise(resolve=>{release=resolve;});}}});
  const request=post(x.url,call(),x.f);await pending;
  const original=x.f.gate.policy;x.f.gate.policy={version:1,mode:'enforce',rules:[]};
  release({decision:'allow'});
  assert.equal((await request).status,403);assert.equal(x.store.count(),0);
  x.f.gate.policy=original;
  assert.equal((await post(x.url,call(),x.f)).status,200);assert.equal(x.store.count(),1);
});
test('approval expiry during external policy wait prevents execution',async t=>{
  let release,started;let time=Math.floor(Date.now()/1000);
  const pending=new Promise(resolve=>{started=resolve;});const approver=newIdentity();
  const x=await system(t,{now:()=>time,approvalConfig:{approverKeys:{reviewer:approver.publicPem},quorum:1},
    externalPolicy:{authorize:()=>{started();return new Promise(resolve=>{release=resolve;});}}});
  const approval=signApproval({approver:'reviewer',privatePem:approver.privatePem,capability:x.f.capability,agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,now:time,ttl:1});
  const request=post(x.url,call(),{...x.f,headers:{'x-faraday-approvals':encodeApprovals([approval])}});await pending;
  time++;release({decision:'allow'});
  assert.equal((await request).status,403);assert.equal(x.store.count(),0);
});
test('emergency stop during external policy wait prevents execution',async t=>{
  let release,started,blocked=false;
  const pending=new Promise(resolve=>{started=resolve;});
  const sentinel={isBlocked:()=>blocked,record:()=>{}};
  const x=await system(t,{sentinel,externalPolicy:{authorize:()=>{started();return new Promise(resolve=>{release=resolve;});}}});
  const request=post(x.url,call(),x.f);await pending;
  blocked=true;release({decision:'allow'});
  assert.equal((await request).status,403);assert.equal(x.store.count(),0);
});
test('OAuth expiry during external policy wait prevents execution',async t=>{
  let release,started,expired=false,checks=0;
  const pending=new Promise(resolve=>{started=resolve;});
  const oauthResource={executeScope:'execute',readScope:'read',verifyAuthorization:()=>{checks++;if(expired)throw Error('expired');return {subject:AGENT};}};
  const x=await system(t,{oauthResource,externalPolicy:{authorize:()=>{started();return new Promise(resolve=>{release=resolve;});}}});
  const request=post(x.url,call(),x.f);await pending;
  expired=true;release({decision:'allow'});
  assert.equal((await request).status,403);assert.equal(checks,2);assert.equal(x.store.count(),0);
});
test('missing proof is denied without forwarding',async t=>{
  const x=await system(t);assert.equal((await post(x.url,call())).status,403);assert.equal(x.store.count(),0);
});
test('MCP server/discover and tools list work with 2026 transport fields',async t=>{
  const x=await system(t);const init=await post(x.url,rpc('server/discover'));
  assert.equal(init.status,200);assert.deepEqual(init.json.result.supportedVersions,[VERSION,'2025-11-25']);
  const list=await post(x.url,rpc('tools/list'));assert.equal(list.status,200);assert.equal(list.json.result.tools[0].name,'pay_invoice');
});
test('legacy 2025 protocol version supported for tool calls',async t=>{
  const x=await system(t);const r=await post(x.url,call(),{...x.f,headers:{'mcp-protocol-version':'2025-11-25'}});assert.equal(r.status,200);
});
test('MCP version/header mismatch denied',async t=>{
  const x=await system(t);const r=await post(x.url,call(),{...x.f,headers:{'mcp-name':'different'}});
  assert.equal(r.status,400);assert.equal(x.store.count(),0);
});
test('browser origin denied by default',async t=>{
  const x=await system(t);const r=await post(x.url,call(),{...x.f,headers:{origin:'https://malicious.example'}});
  assert.equal(r.status,403);assert.equal(x.store.count(),0);
});
test('backend durable idempotency survives reopen',t=>{
  const dir=mkdtempSync(join(tmpdir(),'faraday-backend-'));
  const db=join(dir,'stable.sqlite'),body={operationId:'synthetic-operation-123456789',tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS};
  const a=new DurableSyntheticStore(db);assert.equal(a.apply(body).duplicate,false);a.close();
  const b=new DurableSyntheticStore(db);t.after(()=>{b.close();rmSync(dir,{recursive:true,force:true});});assert.equal(b.apply(body).duplicate,true);assert.equal(b.count(),1);
  assert.equal(b.apply({...body,args:{...ARGS,amount_cents:9000}}).http,409);
});
test('backend denies direct calls without service secret',async t=>{
  const x=await system(t);const r=await fetch(x.backendUrl+'/internal/execute',{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
  assert.equal(r.status,401);assert.equal(x.store.count(),0);
});
test('receipt tampering and incorrect verification key are rejected',async t=>{
  const x=await system(t);const r=await post(x.url,call(),x.f);const receipt=r.json.result.structuredContent.receipt;
  assert.throws(()=>verifyReceipt({receipt:{...receipt,claims:{...receipt.claims,outcome:'upstream-uncertain'}},publicPem:x.receiptKey.publicPem}),/invalid-receipt-signature/);
  assert.throws(()=>verifyReceipt({receipt,publicPem:newIdentity().publicPem}),/invalid-receipt-signature/);
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const altered=receipt.signature.slice(0,-1)+alphabet[alphabet.indexOf(receipt.signature.at(-1))^1];
  assert.deepEqual(Buffer.from(altered,'base64url'),Buffer.from(receipt.signature,'base64url'));
  assert.throws(()=>verifyReceipt({receipt:{...receipt,signature:altered},publicPem:x.receiptKey.publicPem,backendPublicPem:x.backendKey.publicPem}),/invalid-receipt-signature/);
});
test('malformed backend response yields signed uncertain receipt stored in journal',async t=>{
  const x=await system(t,{fetchFn:async()=>new Response('garbage',{status:200})});
  const r=await post(x.url,call(),x.f);assert.equal(r.status,503);assert.equal(x.store.count(),0);
  const record=x.journal.get(x.f.gate.ledger.db.prepare('SELECT key FROM consumed WHERE key LIKE \'cap:%\'').get().key.slice(4));
  assert.equal(record.state,'upstream-uncertain');assert.equal(verifyReceipt({publicPem:x.receiptKey.publicPem,receipt:record.receipt}).outcome,'upstream-uncertain');
});
test('bound response size and upstream error fail closed',async t=>{
  const x=await system(t,{fetchFn:async()=>new Response('a'.repeat(20_000),{status:200})});
  const r=await post(x.url,call(),x.f);assert.equal(r.status,503);
});
test('journal prevents using same operation id twice even with process restart',t=>{
  const x=setup(t);const id='jti-12345678901234567890123';x.journal.reserve(id,'h1');
  assert.throws(()=>x.journal.reserve(id,'h1'),/operation-already-reserved/);
  const another=new ExecutionJournal(join(x.root,'journal.sqlite'));x.additional.push(another);assert.throws(()=>another.reserve(id,'h1'),/operation-already-reserved/);
});
test('backend refuses conflicting idempotency keys',t=>{
  const x=setup(t);const id='jti-12345678901234567890123';
  assert.equal(x.store.apply({operationId:id,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS}).http,200);
  assert.equal(x.store.apply({operationId:id,tool:TOOL,resource:RESOURCE,action:ACTION,args:{...ARGS,amount_cents:9501}}).http,409);
});

test('backend cannot forge success without its own signing key',async t=>{
  const x=await system(t,{fetchFn:async()=>new Response(JSON.stringify({status:'simulated',operationId:'anything',requestHash:'anything'}),{status:200,headers:{'content-type':'application/json'}})});
  const r=await post(x.url,call(),x.f);assert.equal(r.status,503);assert.equal(x.store.count(),0);
});
test('backend success response missing attestation is not accepted',async t=>{
  const x=await system(t,{fetchFn:async(_url,opts)=>{
    const upstream=await fetch(x.backendUrl+'/internal/execute',opts);
    const result=await upstream.json();delete result.attestation;
    return new Response(JSON.stringify(result),{status:200,headers:{'content-type':'application/json'}});
  }});
  const r=await post(x.url,call(),x.f);assert.equal(r.status,503);assert.equal(x.store.count(),1);
});
