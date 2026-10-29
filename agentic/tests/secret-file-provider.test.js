import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,writeFileSync,symlinkSync,chmodSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createStrictSecretFileProvider} from '../lib/secret-file-provider.js';
import {DurableSyntheticStore,createDurableSyntheticBackend} from '../lib/pilot-backend.js';
import {newIdentity,digest} from '../lib/authority.js';
const secretA='A'.repeat(40),secretB='B'.repeat(40);
function files(t){const dir=mkdtempSync(join(tmpdir(),'faraday-secret-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));const path=join(dir,'secret');writeFileSync(path,secretA,{mode:0o600});return {dir,path,provider:createStrictSecretFileProvider(path)};}
test('secret file provider reads on demand and changes immediately after controlled rotation',t=>{
 const x=files(t);assert.equal(x.provider(),secretA);writeFileSync(x.path,secretB,{mode:0o600});assert.equal(x.provider(),secretB);
});
test('nonexistent, symlink, world-readable and invalid credentials fail closed',t=>{
 const x=files(t),link=join(x.dir,'link');symlinkSync(x.path,link);
 assert.throws(()=>createStrictSecretFileProvider(link)(),/unsafe/);
 if(process.platform!=='win32'){
  chmodSync(x.path,0o644);assert.throws(()=>x.provider(),/permissions/);chmodSync(x.path,0o600);
 }
 writeFileSync(x.path,'short',{mode:0o600});assert.throws(()=>x.provider(),/credential/);
});
test('real backend enforces rotated credential and never returns secret in responses',async t=>{
 const x=files(t),store=new DurableSyntheticStore(join(x.dir,'operations.db')),backendKey=newIdentity();t.after(()=>store.close());
 const server=createDurableSyntheticBackend({secretProvider:x.provider,store,attestationPrivatePem:backendKey.privatePem});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
 const target=`http://127.0.0.1:${server.address().port}/internal/status`;
 const req=async password=>{const r=await fetch(target,{method:'POST',headers:{'authorization':`Bearer ${password}`,'content-type':'application/json'},body:JSON.stringify({operationId:'operation-1234567890123456',requestHash:digest({foo:'bar'})})});return {status:r.status,text:await r.text()};};
 assert.equal((await req(secretA)).status,404);
 writeFileSync(x.path,secretB,{mode:0o600});
 assert.equal((await req(secretA)).status,401);
 assert.equal((await req(secretB)).status,404);
 assert.equal((await req(secretB)).text.includes(secretB),false);
});

test('gateway/backend secret mismatch preserves fail-closed journal and a fresh capability succeeds after rotation',async t=>{
 const {fixture,AGENT,ARGS,TOOL,RESOURCE,ACTION}=await import('../lib/authority-fixture.js');
 const {createIntent,createExecution}=await import('../lib/authority.js');
 const {createSecurePilotGateway}=await import('../lib/pilot-mcp.js');
 const {ExecutionJournal}=await import('../lib/pilot-receipts.js');
 const root=mkdtempSync(join(tmpdir(),'faraday-secret-gateway-'));t.after(()=>rmSync(root,{recursive:true,force:true}));
 const gFile=join(root,'gateway-secret'),bFile=join(root,'backend-secret');
 writeFileSync(gFile,secretA,{mode:0o600});writeFileSync(bFile,secretA,{mode:0o600});
 const f=fixture(root),journal=new ExecutionJournal(join(root,'journal.sqlite')),store=new DurableSyntheticStore(join(root,'backend.sqlite'));
 t.after(()=>{f.close();journal.close();store.close();});
 const gatewayKey=newIdentity(),backendKey=newIdentity();
 const backend=createDurableSyntheticBackend({secretProvider:createStrictSecretFileProvider(bFile),store,attestationPrivatePem:backendKey.privatePem});
 await new Promise(r=>backend.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>backend.close(r)));
 const backendUrl=`http://127.0.0.1:${backend.address().port}/internal/execute`;
 const gateway=createSecurePilotGateway({gate:f.gate,backendUrl,backendSecretProvider:createStrictSecretFileProvider(gFile),journal,receiptPrivatePem:gatewayKey.privatePem,backendPublicPem:backendKey.publicPem});
 await new Promise(r=>gateway.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>gateway.close(r)));
 const url=`http://127.0.0.1:${gateway.address().port}/mcp`;
 const call=(capability,proof)=>fetch(url,{method:'POST',headers:{'content-type':'application/json','mcp-protocol-version':'2026-07-28','mcp-method':'tools/call','mcp-name':TOOL,
  'x-faraday-capability':capability,'x-faraday-proof':Buffer.from(JSON.stringify(proof)).toString('base64url')},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:TOOL,arguments:ARGS,_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28'}}})});
 writeFileSync(bFile,secretB,{mode:0o600});
 assert.equal((await call(f.capability,f.proof)).status,503);assert.equal(store.count(),0);
 writeFileSync(gFile,secretB,{mode:0o600});
 assert.equal((await call(f.capability,f.proof)).status,403);assert.equal(store.count(),0);
 const intent=createIntent({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,agentPrivatePem:f.agent.privatePem});
 const fresh=f.iss.issue(intent);
 const nextProof=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,capability:fresh,agentPrivatePem:f.agent.privatePem});
 assert.equal((await call(fresh,nextProof)).status,200);assert.equal(store.count(),1);
});
