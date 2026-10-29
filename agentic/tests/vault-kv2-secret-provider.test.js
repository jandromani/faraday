import test from 'node:test';import assert from 'node:assert/strict';import http from 'node:http';
import {mkdtempSync,rmSync,writeFileSync,chmodSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {createVaultKv2SecretProvider} from '../lib/vault-kv2-secret-provider.js';
const A='x'.repeat(48),B='y'.repeat(48);
async function fixture(t){
 const root=mkdtempSync(join(tmpdir(),'faraday-vault-kv2-')),tokenFile=join(root,'vault-token');
 writeFileSync(tokenFile,'hvs.TEST12345678901234567890',{mode:0o600});
 let secret=A,status=200,requests=0,version=1,contentType='application/json',reply=null;
 const server=http.createServer((req,res)=>{
  requests++;
  if(req.url!=='/v1/faraday/data/gateway/backend'||req.headers['x-vault-token']!=='hvs.TEST12345678901234567890'){res.writeHead(403);return res.end('no');}
  if(status!==200){res.writeHead(status,{location:'http://127.0.0.1:1/stolen'});return res.end('no');}
  res.writeHead(200,{'content-type':contentType});
  res.end(JSON.stringify(reply??{data:{data:{backend_credential:secret},metadata:{version}}}));
 });
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 t.after(async()=>{await new Promise(r=>server.close(r));rmSync(root,{recursive:true,force:true});});
 return {tokenFile,opts:{baseUrl:'http://127.0.0.1:'+server.address().port,mount:'faraday',secretPath:'gateway/backend',tokenFile,allowLoopbackHttp:true},
  controls:{get requests(){return requests;},set secret(x){secret=x;},set status(x){status=x;},set version(x){version=x;},set contentType(x){contentType=x;},set reply(x){reply=x;}}};
}
test('read versioned Vault secret and rotate without restart',async t=>{const x=await fixture(t),p=createVaultKv2SecretProvider(x.opts);assert.equal(await p(),A);x.controls.secret=B;assert.equal(await p(),B);assert.equal(x.controls.requests,2);});
test('deny redirects to prevent token exfiltration',async t=>{const x=await fixture(t);x.controls.status=302;await assert.rejects(createVaultKv2SecretProvider(x.opts)(),/vault-credential-unavailable/);assert.equal(x.controls.requests,1);});
test('deny revoked token and invalid response version and type',async t=>{const x=await fixture(t),p=createVaultKv2SecretProvider(x.opts);x.controls.status=403;await assert.rejects(p(),/vault-credential-unavailable/);x.controls.status=200;x.controls.version=0;await assert.rejects(p(),/vault-credential-unavailable/);x.controls.version=1;x.controls.contentType='text/html';await assert.rejects(p(),/vault-credential-unavailable/);});
test('deny oversized bodies and wrong credential field',async t=>{const x=await fixture(t),p=createVaultKv2SecretProvider({...x.opts,maxResponseBytes:1024});x.controls.reply={data:{data:{backend_credential:'z'.repeat(1500)},metadata:{version:3}}};await assert.rejects(p(),/vault-credential-unavailable/);x.controls.reply={data:{data:{wrong_field:A},metadata:{version:3}}};await assert.rejects(p(),/vault-credential-unavailable/);});
test('reject group-readable token file',async t=>{const x=await fixture(t);if(process.platform==='win32')return t.skip('POSIX perms only');chmodSync(x.tokenFile,0o644);await assert.rejects(createVaultKv2SecretProvider(x.opts)(),/vault-credential-unavailable/);});
test('reject plaintext remote URLs, credentials and traversal',async t=>{const x=await fixture(t);for(const baseUrl of ['http://vault.example.com','https://u:p@vault.example.com','https://vault.example.com/?key=one','http://169.254.169.254','ftp://vault.example.com'])assert.throws(()=>createVaultKv2SecretProvider({...x.opts,baseUrl}),/invalid-vault-url/);assert.throws(()=>createVaultKv2SecretProvider({...x.opts,mount:'../root'}),/invalid-vault-configuration/);});
test('deny Vault outage instead of stale fallback',async t=>{const x=await fixture(t);await assert.rejects(createVaultKv2SecretProvider({...x.opts,fetchFn:async()=>{throw Error('network outage');}})(),/vault-credential-unavailable/);});
