import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createPrivateKey,sign} from 'node:crypto';
import {spawn,spawnSync} from 'node:child_process';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createInterface} from 'node:readline';
import {fixture,AGENT,ARGS,TOOL,RESOURCE,ACTION,POLICY} from '../lib/authority-fixture.js';
import {createExecution,newIdentity,AuthorityError,NonceLedger,canonical,digest} from '../lib/authority.js';
import {ExecutionJournal,signReceipt,verifyReceipt} from '../lib/pilot-receipts.js';
import {DurableSyntheticStore,createDurableSyntheticBackend} from '../lib/pilot-backend.js';
import {createSecurePilotGateway} from '../lib/pilot-mcp.js';
import {signApproval,encodeApprovals} from '../lib/approvals.js';
import {signBackendAttestation} from '../lib/backend-attestation.js';
import {createVaultKv2SecretProvider} from '../lib/vault-kv2-secret-provider.js';
import {reconcileSyntheticOperation} from '../lib/pilot-reconcile.js';

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
test('receipt verifier rejects signed incompatible claim schemas',async t=>{
  const x=await system(t);const response=await post(x.url,call(),x.f);
  const receipt=response.json.result.structuredContent.receipt;
  const mergedFields=Object.fromEntries(Object.entries(receipt.claims).filter(([key])=>!['agent','argsHash'].includes(key)));
  mergedFields['agent|argsHash']='synthetic';
  for(const claims of [{...receipt.claims,unexpected:'value'},{...receipt.claims,version:2},Object.fromEntries(Object.entries(receipt.claims).filter(([key])=>key!=='agent')),mergedFields]){
    const bytes=Buffer.concat([Buffer.from('FARADAY-RECEIPT-V095\0'),canonical(claims)]);
    const incompatible={claims,signature:sign(null,bytes,createPrivateKey(x.receiptKey.privatePem)).toString('base64url')};
    assert.throws(()=>verifyReceipt({publicPem:x.receiptKey.publicPem,receipt:incompatible,backendPublicPem:x.backendKey.publicPem}),/invalid-receipt/);
  }
});
test('signed simulated receipts require independent backend evidence and key',async t=>{
  const x=await system(t);const response=await post(x.url,call(),x.f),receipt=response.json.result.structuredContent.receipt;
  const unsupported=signReceipt({privatePem:x.receiptKey.privatePem,claims:{...receipt.claims,backendAttestation:null,responseHash:null}});
  assert.throws(()=>verifyReceipt({publicPem:x.receiptKey.publicPem,receipt:unsupported}),/backend-proof-not-verified/);
  assert.throws(()=>verifyReceipt({publicPem:x.receiptKey.publicPem,backendPublicPem:x.backendKey.publicPem,receipt:unsupported}),/backend-proof-not-verified/);
  assert.throws(()=>verifyReceipt({publicPem:x.receiptKey.publicPem,receipt}),/backend-key-required/);
  assert.equal(verifyReceipt({publicPem:x.receiptKey.publicPem,backendPublicPem:x.backendKey.publicPem,receipt}).backendVerified,true);
  const attestation=signBackendAttestation({privatePem:x.receiptKey.privatePem,claims:receipt.claims.backendAttestation.claims});
  const sharedKey=signReceipt({privatePem:x.receiptKey.privatePem,claims:{...receipt.claims,backendAttestation:attestation,responseHash:digest(attestation)}});
  assert.throws(()=>verifyReceipt({publicPem:x.receiptKey.publicPem,backendPublicPem:x.receiptKey.publicPem,receipt:sharedKey}),/backend-key-not-independent/);
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
test('persistent agent revocation during external policy wait prevents execution',async t=>{
  let release,started;
  const pending=new Promise(resolve=>{started=resolve;});
  const x=await system(t,{externalPolicy:{authorize:()=>{started();return new Promise(resolve=>{release=resolve;});}}});
  const request=post(x.url,call(),x.f);await pending;
  const writer=new NonceLedger(join(x.root,'gateway.sqlite'));x.additional.push(writer);
  writer.revoke('agent',AGENT);
  release({decision:'allow'});
  assert.equal((await request).status,403);assert.equal(x.store.count(),0);
  assert.equal(writer.db.prepare('SELECT COUNT(*) AS n FROM consumed').get().n,0);
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
test('backend deduplicates concurrent independent processes sharing one SQLite database',async t=>{
  const x=setup(t),moduleUrl=pathToFileURL(join(process.cwd(),'lib','pilot-backend.js')).href;
  const script=`import {DurableSyntheticStore} from ${JSON.stringify(moduleUrl)};
let input='';for await(const chunk of process.stdin)input+=chunk;
const config=JSON.parse(input),store=new DurableSyntheticStore(config.path);
try{process.stdout.write(JSON.stringify(store.apply(config.body)));}finally{store.close();}`;
  const config=JSON.stringify({path:join(x.root,'backend.sqlite'),body:{operationId:'concurrent-operation-123456789',tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS}});
  const results=await Promise.all(Array.from({length:6},()=>new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,['--no-warnings','--input-type=module','-e',script],{stdio:['pipe','pipe','pipe']});
    let output='',errors='';child.stdout.on('data',chunk=>output+=chunk);child.stderr.on('data',chunk=>errors+=chunk);
    child.on('error',reject);child.on('close',code=>{if(code!==0)return reject(Error(errors||`exit ${code}`));try{resolve(JSON.parse(output));}catch(error){reject(error);}});
    child.stdin.end(config);
  })));
  assert.equal(results.filter(result=>result.http===200&&!result.duplicate).length,1);
  assert.equal(results.filter(result=>result.http===200&&result.duplicate).length,5);assert.equal(x.store.count(),1);
  assert.equal(x.store.apply({operationId:'concurrent-operation-123456789',tool:TOOL,resource:RESOURCE,action:ACTION,args:{...ARGS,amount_cents:9000}}).http,409);
});
test('journal failure after backend execution leaves a reservation without replay',async t=>{
  const x=await system(t);
  x.journal.db.exec("CREATE TRIGGER reject_finish BEFORE UPDATE ON executions BEGIN SELECT RAISE(FAIL,'journal unavailable'); END");
  assert.equal((await post(x.url,call(),x.f)).status,503);assert.equal(x.store.count(),1);
  const operationId=x.f.gatewayLedger.db.prepare("SELECT key FROM consumed WHERE key LIKE 'cap:%'").get().key.slice(4);
  const reopened=new ExecutionJournal(join(x.root,'journal.sqlite'));x.additional.push(reopened);
  assert.equal(reopened.get(operationId).state,'reserved');assert.equal(reopened.get(operationId).receipt,null);
  assert.equal((await post(x.url,call(),x.f)).status,403);assert.equal(x.store.count(),1);
  let contacted=false;
  await assert.rejects(reconcileSyntheticOperation({operationId,journal:reopened,backendUrl:x.backendUrl+'/internal/execute',backendSecret:x.f.backendSecret,backendPublicPem:x.backendKey.publicPem,receiptPrivatePem:x.receiptKey.privatePem,receiptPublicPem:x.receiptKey.publicPem,fetchFn:()=>{contacted=true;}}),/operation-not-reconcilable/);
  assert.equal(contacted,false);
});
test('gateway process killed after backend execution leaves an unresolved reservation',async t=>{
  const x=setup(t),backend=createDurableSyntheticBackend({secret:x.f.backendSecret,store:x.store,attestationPrivatePem:x.backendKey.privatePem});
  const backendUrl=await listen(t,backend),authority=pathToFileURL(join(process.cwd(),'lib','authority.js')).href,
    journalModule=pathToFileURL(join(process.cwd(),'lib','pilot-receipts.js')).href,pilot=pathToFileURL(join(process.cwd(),'lib','pilot-mcp.js')).href;
  const script=`import {AuthorityGate,NonceLedger} from ${JSON.stringify(authority)};
import {ExecutionJournal} from ${JSON.stringify(journalModule)};
import {createSecurePilotGateway} from ${JSON.stringify(pilot)};
let input='';for await(const chunk of process.stdin)input+=chunk;
const config=JSON.parse(input),ledger=new NonceLedger(config.ledgerPath),journal=new ExecutionJournal(config.journalPath);
const gate=new AuthorityGate({issuerKeys:config.issuerKeys,registry:config.registry,policy:config.policy,ledger});
const server=createSecurePilotGateway({gate,journal,backendUrl:config.backendUrl,backendSecret:config.backendSecret,receiptPrivatePem:config.receiptPrivatePem,backendPublicPem:config.backendPublicPem,
fetchFn:async(url,options)=>{const response=await fetch(url,options);await response.arrayBuffer();console.log('backend-applied');await new Promise(()=>{});}});
server.listen(0,'127.0.0.1',()=>console.log('ready:'+server.address().port));`;
  const child=spawn(process.execPath,['--no-warnings','--input-type=module','-e',script],{stdio:['pipe','pipe','pipe']});
  t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});
  const lines=createInterface({input:child.stdout})[Symbol.asyncIterator]();
  child.stdin.end(JSON.stringify({ledgerPath:join(x.root,'gateway.sqlite'),journalPath:join(x.root,'journal.sqlite'),issuerKeys:{'lab-issuer':x.f.issuer.publicPem},registry:x.f.registry,policy:POLICY,backendUrl:backendUrl+'/internal/execute',backendSecret:x.f.backendSecret,receiptPrivatePem:x.receiptKey.privatePem,backendPublicPem:x.backendKey.publicPem}));
  const ready=(await lines.next()).value;assert.match(ready??'',/^ready:\d+$/);
  const request=post('http://127.0.0.1:'+ready.slice(6),call(),x.f).catch(()=>null);
  assert.equal((await lines.next()).value,'backend-applied');assert.equal(x.store.count(),1);
  const exited=new Promise(resolve=>child.once('exit',resolve));child.kill('SIGKILL');await exited;await request;
  const operationId=x.f.gatewayLedger.db.prepare("SELECT key FROM consumed WHERE key LIKE 'cap:%'").get().key.slice(4);
  assert.equal(x.journal.get(operationId).state,'reserved');assert.equal(x.journal.get(operationId).receipt,null);
  assert.throws(()=>x.f.gate.authorize({capability:x.f.capability,proof:x.f.proof}),/replayed/);
  assert.equal(x.store.count(),1);
});
test('backend denies direct calls without service secret',async t=>{
  const x=await system(t);const r=await fetch(x.backendUrl+'/internal/execute',{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
  assert.equal(r.status,401);assert.equal(x.store.count(),0);
});
test('backend entrypoint rejects a non-file service credential',t=>{
  const x=setup(t),script=fileURLToPath(new URL('../bin/faraday-pilot-backend.js',import.meta.url));
  const result=spawnSync(process.execPath,[script],{encoding:'utf8',env:{...process.env,FARADAY_BACKEND_SECRET_FILE:x.root,FARADAY_BACKEND_DB:join(x.root,'unused.sqlite')}});
  assert.notEqual(result.status,0);assert.match(result.stderr,/unsafe-key-file/);
});
test('pilot entrypoints reject unsafe secret and backend signing-key files',t=>{
  const x=setup(t),secret=join(x.root,'secret'),policy=join(x.root,'policy.json'),config=join(x.root,'config.json');
  writeFileSync(secret,x.f.backendSecret,{mode:0o600});writeFileSync(policy,JSON.stringify({version:1,mode:'enforce',rules:[]}));
  writeFileSync(config,JSON.stringify({issuerKeys:{},agents:{},policy,nonceDb:join(x.root,'entry-nonce.sqlite'),journalDb:join(x.root,'entry-journal.sqlite'),backendUrl:'http://127.0.0.1/internal/execute',backendSecretFile:x.root}));
  const backend=spawnSync(process.execPath,[fileURLToPath(new URL('../bin/faraday-pilot-backend.js',import.meta.url))],{encoding:'utf8',env:{...process.env,FARADAY_BACKEND_SECRET_FILE:secret,FARADAY_BACKEND_ATTESTATION_PRIVATE_FILE:x.root}});
  const gateway=spawnSync(process.execPath,[fileURLToPath(new URL('../bin/faraday-pilot-gateway.js',import.meta.url))],{encoding:'utf8',env:{...process.env,FARADAY_PILOT_CONFIG:config}});
  for(const result of [backend,gateway]){assert.notEqual(result.status,0);assert.match(result.stderr,/unsafe-key-file/);assert.ok(!result.stderr.includes(x.f.backendSecret));}
});
test('a direct caller with the service credential bypasses gateway authorization',async t=>{
  const x=await system(t),body={operationId:'direct-operation-123456789',tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS};
  const response=await fetch(x.backendUrl+'/internal/execute',{method:'POST',headers:{'content-type':'application/json',authorization:`Bearer ${x.f.backendSecret}`},body:JSON.stringify(body)});
  assert.equal(response.status,200);assert.equal(x.store.count(),1);
});
test('backend redirect does not forward the service credential',async t=>{
  let received=0;
  const destination=await listen(t,http.createServer((req,res)=>{received++;res.end('unexpected');}));
  const redirect=await listen(t,http.createServer((_req,res)=>{res.writeHead(307,{location:destination+'/internal/execute'});res.end();}));
  const x=await system(t,{backendUrl:redirect+'/internal/execute'});
  const response=await post(x.url,call(),x.f);
  assert.equal(response.status,503);assert.equal(received,0);assert.equal(x.store.count(),0);
  assert.ok(!JSON.stringify(response).includes(x.f.backendSecret));
});
test('upstream errors and responses do not reflect the service credential',async t=>{
  let secret;const events=[];
  const x=await system(t,{onEvent:event=>events.push(event),fetchFn:async(_url,options)=>{
    secret=options.headers.authorization.slice('Bearer '.length);
    return new Response(JSON.stringify({status:'error',message:secret}),{status:500});
  }});
  const response=await post(x.url,call(),x.f);
  assert.equal(response.status,503);assert.equal(x.store.count(),0);
  assert.equal(secret,x.f.backendSecret);
  assert.ok(!JSON.stringify({response,events}).includes(secret));
});
test('credential provider failure does not spend authority and recovery succeeds',async t=>{
  let unavailable=true,x;
  x=await system(t,{backendSecret:undefined,backendSecretProvider:async()=>{if(unavailable)throw Error('sensitive token');return x.f.backendSecret;}});
  const failed=await post(x.url,call(),x.f);assert.equal(failed.status,503);assert.ok(!JSON.stringify(failed).includes('sensitive token'));
  assert.equal(x.store.count(),0);assert.equal(x.f.gatewayLedger.db.prepare('SELECT count(*) AS n FROM consumed').get().n,0);
  unavailable=false;assert.equal((await post(x.url,call(),x.f)).status,200);assert.equal(x.store.count(),1);
});
test('gateway reads a KV v2 fixture and fails closed on revoked token',async t=>{
  const root=mkdtempSync(join(tmpdir(),'faraday-vault-integration-')),tokenFile=join(root,'token');
  writeFileSync(tokenFile,'hvs.TEST12345678901234567890',{mode:0o600});
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  let secret,status=403,requests=0;
  const vault=await listen(t,http.createServer((req,res)=>{
    requests++;
    if(req.url!=='/v1/secret/data/gateway/backend'||req.headers['x-vault-token']!=='hvs.TEST12345678901234567890'||status!==200){res.writeHead(403);return res.end();}
    res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({data:{data:{backend_credential:secret},metadata:{version:1}}}));
  }));
  const provider=createVaultKv2SecretProvider({baseUrl:vault,secretPath:'gateway/backend',tokenFile,allowLoopbackHttp:true});
  const x=await system(t,{backendSecret:undefined,backendSecretProvider:provider});secret=x.f.backendSecret;
  assert.equal((await post(x.url,call(),x.f)).status,503);assert.equal(x.store.count(),0);
  status=200;const result=await post(x.url,call(),x.f);assert.equal(result.status,200);assert.equal(x.store.count(),1);
  assert.equal(requests,2);assert.ok(!JSON.stringify(result).includes(secret));
});
test('revocation during credential lookup prevents authorization and backend calls',async t=>{
  let release,started;const waiting=new Promise(resolve=>started=resolve);
  let x;x=await system(t,{backendSecret:undefined,backendSecretProvider:()=>new Promise(resolve=>{release=()=>resolve(x.f.backendSecret);started();})});
  const pending=post(x.url,call(),x.f);await waiting;x.f.gatewayLedger.revoke('agent',AGENT);release();
  assert.equal((await pending).status,403);assert.equal(x.store.count(),0);
  assert.equal(x.f.gatewayLedger.db.prepare('SELECT count(*) AS n FROM consumed').get().n,0);
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
test('E26 socket loss after committed backend effect stays uncertain and replay does not repeat it',async t=>{
  let x;
  const proxy=await listen(t,http.createServer((request,response)=>{
    const upstream=http.request(x.backendUrl+'/internal/execute',{method:request.method,headers:request.headers},upstreamResponse=>{
      upstreamResponse.resume();response.socket.destroy();
    });
    upstream.on('error',()=>response.destroy());request.pipe(upstream);
  }));
  x=await system(t,{backendUrl:proxy+'/internal/execute'});
  assert.equal((await post(x.url,call(),x.f)).status,503);assert.equal(x.store.count(),1);
  const key=x.f.gate.ledger.db.prepare("SELECT key FROM consumed WHERE key LIKE 'cap:%'").get().key.slice(4);
  const record=x.journal.get(key);assert.equal(record.state,'upstream-uncertain');
  assert.equal(verifyReceipt({publicPem:x.receiptKey.publicPem,receipt:record.receipt}).outcome,'upstream-uncertain');
  assert.equal((await post(x.url,call(),x.f)).status,403);assert.equal(x.store.count(),1);
});
