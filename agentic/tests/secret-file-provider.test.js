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
