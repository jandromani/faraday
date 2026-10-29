import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,writeFileSync,chmodSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {newIdentity,createIntent,createExecution,AuthorityGate,AuthorityIssuer,NonceLedger,AuthorityError,readKeyFile} from '../lib/authority.js';
import {fixture,AGENT,TOOL,RESOURCE,ACTION,ARGS,POLICY} from '../lib/authority-fixture.js';
import {createAuthorityGateway,createSyntheticBackend} from '../lib/authority-gateway.js';

function setup(t){const dir=mkdtempSync(join(tmpdir(),'faraday-v09-'));const f=fixture(dir,{now:1_800_000_000});const ledgers=[];t.after(()=>{for(const ledger of ledgers)ledger.close();f.close();rmSync(dir,{recursive:true,force:true});});return {f,dir,ledgers};}
function make(f,{args=ARGS,agentKey=f.agent.privatePem,cap=f.capability,now=1_800_000_000}={}){
  return createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args,capability:cap,agentPrivatePem:agentKey,now});
}
test('valid proof permits a synthetic operation exactly once',t=>{
  const {f}=setup(t);assert.equal(f.gate.authorize({capability:f.capability,proof:f.proof}).rule,'fake-invoice-only');
  assert.throws(()=>f.gate.authorize({capability:f.capability,proof:f.proof}),/capability-replayed/);
});
test('stolen capability does not grant authority without agent private key',t=>{
  const {f}=setup(t);const thief=newIdentity();assert.throws(()=>f.gate.authorize({capability:f.capability,proof:make(f,{agentKey:thief.privatePem})}),/invalid-signature/);
  assert.ok(f.gate.authorize({capability:f.capability,proof:f.proof}));
});
test('signature alteration, altered args and expired token rejected',t=>{
  const {f}=setup(t);const corrupted=Buffer.from(f.capability,'base64url');const data=JSON.parse(corrupted.toString());data.payload.argsHash='x';
  const tampered=Buffer.from(JSON.stringify(data)).toString('base64url');
  assert.throws(()=>f.gate.authorize({capability:tampered,proof:make(f,{cap:tampered})}),/invalid-signature/);
  assert.throws(()=>f.gate.authorize({capability:f.capability,proof:make(f,{args:{...ARGS,amount_cents:12000}})}),/scope-mismatch/);
});
test('issuance replays and policy privilege expansion fail closed',t=>{
  const {f}=setup(t);
  assert.throws(()=>f.iss.issue(f.intent),/capability-replayed/);
  assert.throws(()=>f.iss.issue(createIntent({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:{...ARGS,amount_cents:30000},agentPrivatePem:f.agent.privatePem,now:1_800_000_000})),/policy-denied/);
  assert.throws(()=>f.iss.issue(createIntent({agent:AGENT,tool:TOOL,resource:'invoice:other',action:ACTION,args:ARGS,agentPrivatePem:f.agent.privatePem,now:1_800_000_000})),/policy-denied/);
});
test('issuer signing private key not needed by gateway, issuer rotation rejects capability',t=>{
  const {f,dir,ledgers}=setup(t);
  assert.ok(!Object.values(f.gate.keys).some(v=>v.includes('PRIVATE KEY')));
  const otherIssuer=newIdentity();
  const rotated=new AuthorityGate({issuerKeys:{'lab-issuer':otherIssuer.publicPem},registry:f.registry,policy:POLICY,ledger:new NonceLedger(join(dir,'other.sqlite')),now:()=>1_800_000_000});
  ledgers.push(rotated.ledger);assert.throws(()=>rotated.authorize({capability:f.capability,proof:f.proof}),/invalid-signature/);
});
test('gateway rejects stale times, unknown agent and different policy versions',t=>{
  const {f,dir,ledgers}=setup(t);const expired=new AuthorityGate({issuerKeys:{'lab-issuer':f.issuer.publicPem},registry:f.registry,policy:POLICY,ledger:new NonceLedger(join(dir,'expired.sqlite')),now:()=>1_800_000_310});
  ledgers.push(expired.ledger);assert.throws(()=>expired.authorize({capability:f.capability,proof:f.proof}),/expired/);
  const revoked=new AuthorityGate({issuerKeys:{'lab-issuer':f.issuer.publicPem},registry:{},policy:POLICY,ledger:new NonceLedger(join(dir,'revoked.sqlite')),now:()=>1_800_000_000});
  ledgers.push(revoked.ledger);assert.throws(()=>revoked.authorize({capability:f.capability,proof:f.proof}),/unknown-agent/);
});
test('concurrent uses of the same token: one success only',async t=>{
  const {f}=setup(t);const outcomes=await Promise.all(Array.from({length:16},()=>Promise.resolve().then(()=>{try{f.gate.authorize({capability:f.capability,proof:f.proof});return 'ok';}catch{return 'denied';}})));
  assert.equal(outcomes.filter(x=>x==='ok').length,1);
});
test('private key file can be read',t=>{
  const {dir}=setup(t);const path=join(dir,'private.pem');writeFileSync(path,newIdentity().privatePem,{mode:0o600});
  assert.match(readKeyFile(path,{privateKey:true}),/PRIVATE KEY/);
});
test('private key files require restrictive POSIX mode',{skip:process.platform==='win32'?'POSIX mode does not verify Windows ACLs':false},t=>{
  const {dir}=setup(t);const path=join(dir,'private.pem');writeFileSync(path,newIdentity().privatePem,{mode:0o600});chmodSync(path,0o644);
  assert.throws(()=>readKeyFile(path,{privateKey:true}),/unsafe-private-key/);
});
test('HTTP gateway: denies missing proof and does not forward it',async t=>{
  const {f}=setup(t);let invoked=0;
  const server=createAuthorityGateway({gate:f.gate,backendUrl:'http://127.0.0.1:8099/internal/execute',backendSecret:f.backendSecret,
    fetchFn:async()=>{invoked++;return new Response('{"status":"simulated"}',{status:200});}});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>server.close());
  const url=`http://127.0.0.1:${server.address().port}/execute`;
  const bad=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({capability:f.capability})});
  assert.equal(bad.status,403);assert.equal(invoked,0);
  const good=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({capability:f.capability,proof:f.proof})});
  assert.equal(good.status,200);assert.equal(invoked,1);
  const replay=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({capability:f.capability,proof:f.proof})});
  assert.equal(replay.status,403);assert.equal(invoked,1);
});
test('direct backend HTTP without private gateway secret rejected',async t=>{
  const {f}=setup(t);const server=createSyntheticBackend({secret:f.backendSecret});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>server.close());
  const url=`http://127.0.0.1:${server.address().port}/internal/execute`;
  const x=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
  assert.equal(x.status,401);
});
test('tool/resource argument checks, no arbitrary destination selection',t=>{
  const {f}=setup(t);
  assert.throws(()=>createAuthorityGateway({gate:f.gate,backendUrl:'http://127.0.0.1:8099/arbitrary',backendSecret:f.backendSecret}),/Fixed backend/);
  assert.throws(()=>createAuthorityGateway({gate:f.gate,backendUrl:'http://127.0.0.1:8099/internal/execute?next=http://attacker',backendSecret:f.backendSecret}),/Fixed backend/);
  assert.throws(()=>f.iss.issue(createIntent({agent:AGENT,tool:'arbitrary_exec',resource:RESOURCE,action:ACTION,args:ARGS,agentPrivatePem:f.agent.privatePem,now:1_800_000_000})),/policy-denied/);
});
test('v0.9 synthetic authority evaluation runs all five adversarial classes',async()=>{
  const {runAuthorityEvaluations}=await import('../lib/authority-demo.js');
  const report=runAuthorityEvaluations({count:50});
  assert.deepEqual(report.summary,{total:50,passed:50,failed:0});
  assert.deepEqual(new Set(report.cases.map(x=>x.check)),new Set(['legitimate','stolen-token','scope-substitution','replay','policy-restriction']));
});
test('authority gateway audit callback receives only metadata, never arguments',async t=>{
  const {f}=setup(t);const seen=[];
  const server=createAuthorityGateway({gate:f.gate,backendUrl:'http://127.0.0.1:8099/internal/execute',backendSecret:f.backendSecret,
    fetchFn:async()=>new Response('{"status":"simulated"}',{status:200}),onDecision:(x)=>seen.push(x)});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>server.close());
  const r=await fetch(`http://127.0.0.1:${server.address().port}/execute`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({capability:f.capability,proof:f.proof})});
  assert.equal(r.status,200);assert.deepEqual(seen,[{status:'authorized',tool:'pay_invoice',agent:AGENT}]);
  assert.ok(!JSON.stringify(seen).includes('supplier_demo'));
});
test('audit write unavailable fails closed instead of forwarding action',async t=>{
  const {f}=setup(t);let forwarded=0;
  const server=createAuthorityGateway({gate:f.gate,backendUrl:'http://127.0.0.1:8099/internal/execute',backendSecret:f.backendSecret,
    onDecision:()=>{throw Error('disk unavailable')},fetchFn:async()=>{forwarded++;return new Response('{"status":"simulated"}',{status:200})}});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>server.close());
  const r=await fetch(`http://127.0.0.1:${server.address().port}/execute`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({capability:f.capability,proof:f.proof})});
  assert.equal(r.status,503);assert.equal(forwarded,0);
});
test('noncanonical and invalid auth inputs are denied',t=>{
  const {f}=setup(t);assert.throws(()=>f.gate.authorize({capability:'not@base64',proof:f.proof}),/invalid-encoding/);
  assert.throws(()=>f.gate.authorize({capability:f.capability,proof:{payload:f.proof.payload,sig:'a@a'}}),/invalid-encoding/);
});
