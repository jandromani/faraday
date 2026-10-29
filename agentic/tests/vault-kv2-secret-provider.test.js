import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {mkdtempSync,rmSync,writeFileSync,chmodSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createVaultKv2SecretProvider} from '../lib/vault-kv2-secret-provider.js';

async function fixture(t){
  const root=mkdtempSync(join(tmpdir(),'faraday-vault-')),tokenFile=join(root,'token');
  writeFileSync(tokenFile,'hvs.TEST12345678901234567890',{mode:0o600});
  const state={secret:'a'.repeat(48),status:200,version:1,requests:0,redirects:0};
  const destination=http.createServer((_req,res)=>{state.redirects++;res.end();});
  await new Promise(resolve=>destination.listen(0,'127.0.0.1',resolve));
  const server=http.createServer((req,res)=>{
    state.requests++;
    if(req.url!=='/v1/faraday/data/gateway/backend'||req.headers['x-vault-token']!=='hvs.TEST12345678901234567890'){res.writeHead(403);return res.end();}
    if(state.status!==200){res.writeHead(state.status,{location:`http://127.0.0.1:${destination.address().port}/stolen`});return res.end();}
    res.writeHead(200,{'content-type':'application/json'});
    res.end(JSON.stringify({data:{data:{backend_credential:state.secret},metadata:{version:state.version}}}));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(async()=>{await new Promise(resolve=>server.close(resolve));await new Promise(resolve=>destination.close(resolve));rmSync(root,{recursive:true,force:true});});
  return {state,options:{baseUrl:`http://127.0.0.1:${server.address().port}`,mount:'faraday',secretPath:'gateway/backend',tokenFile,allowLoopbackHttp:true}};
}
test('KV v2 reads the current version on every request and fails on revocation',async t=>{
  const {state,options}=await fixture(t),provider=createVaultKv2SecretProvider(options);
  assert.equal(await provider(),'a'.repeat(48));state.secret='b'.repeat(48);state.version=2;
  assert.equal(await provider(),'b'.repeat(48));state.status=403;
  await assert.rejects(provider(),/vault-credential-unavailable/);assert.equal(state.requests,3);
});
test('KV v2 rejects redirects without forwarding the token',async t=>{
  const {state,options}=await fixture(t);state.status=307;
  await assert.rejects(createVaultKv2SecretProvider(options)(),/vault-credential-unavailable/);assert.equal(state.redirects,0);
});
test('KV v2 fails closed on invalid responses and unsafe configuration',async t=>{
  const {state,options}=await fixture(t),provider=createVaultKv2SecretProvider(options);
  state.version=0;await assert.rejects(provider(),/vault-credential-unavailable/);
  state.version=1;state.secret='x'.repeat(9000);await assert.rejects(provider(),/vault-credential-unavailable/);
  for(const baseUrl of ['http://vault.example','https://user:pass@vault.example','https://vault.example/?x=1'])assert.throws(()=>createVaultKv2SecretProvider({...options,baseUrl}),/invalid-vault-url/);
  assert.throws(()=>createVaultKv2SecretProvider({...options,secretPath:'../other'}),/invalid-vault-configuration/);
  await assert.rejects(createVaultKv2SecretProvider({...options,fetchFn:async()=>{throw Error('offline');}})(),/vault-credential-unavailable/);
});
const A='x'.repeat(48),B='y'.repeat(48);
async function remoteFixture(t){
  const root=mkdtempSync(join(tmpdir(),'faraday-vault-kv2-'));
  const tokenFile=join(root,'vault-token');writeFileSync(tokenFile,'hvs.TEST12345678901234567890',{mode:0o600});
  let secret=A,status=200,requests=0,version=1,contentType='application/json',reply=null;
  const server=http.createServer((req,res)=>{
    requests++;
    if(req.url!=='/v1/faraday/data/gateway/backend'||req.headers['x-vault-token']!=='hvs.TEST12345678901234567890'){
      res.writeHead(403);return res.end('no');
    }
    if(status!==200){res.writeHead(status,{location:'http://127.0.0.1:1/stolen'});return res.end('not allowed');}
    const payload=reply??{data:{data:{backend_credential:secret},metadata:{version}}};
    res.writeHead(200,{'content-type':contentType});res.end(JSON.stringify(payload));
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  t.after(async()=>{await new Promise(r=>server.close(r));rmSync(root,{recursive:true,force:true});});
  const opts={baseUrl:`http://127.0.0.1:${server.address().port}`,mount:'faraday',secretPath:'gateway/backend',tokenFile,allowLoopbackHttp:true};
  return {tokenFile,opts,controls:{get requests(){return requests},set secret(x){secret=x},set status(x){status=x},set version(x){version=x},set contentType(x){contentType=x},set reply(x){reply=x}}};
}
test('Vault KV v2 protocol fetch reads the versioned value and supports rotation without restart',async t=>{
  const x=await remoteFixture(t);const provider=createVaultKv2SecretProvider(x.opts);
  assert.equal(await provider(),A);x.controls.secret=B;assert.equal(await provider(),B);assert.equal(x.controls.requests,2);
});
test('Vault rejects redirect instead of following it with token',async t=>{
  const x=await remoteFixture(t);const f=createVaultKv2SecretProvider(x.opts);x.controls.status=302;
  await assert.rejects(f(),/vault-credential-unavailable/);assert.equal(x.controls.requests,1);
});
test('Vault fails closed on revoked credentials and invalid response',async t=>{
  const x=await remoteFixture(t);const f=createVaultKv2SecretProvider(x.opts);
  x.controls.status=403;await assert.rejects(f(),/vault-credential-unavailable/);
  x.controls.status=200;x.controls.version=0;await assert.rejects(f(),/vault-credential-unavailable/);
  x.controls.version=1;x.controls.contentType='text/html';await assert.rejects(f(),/vault-credential-unavailable/);
});
test('Vault rejects huge body and unexpected field',async t=>{
  const x=await remoteFixture(t);const f=createVaultKv2SecretProvider({...x.opts,maxResponseBytes:1024});
  x.controls.reply={data:{data:{backend_credential:'z'.repeat(1500)},metadata:{version:3}}};
  await assert.rejects(f(),/vault-credential-unavailable/);
  x.controls.reply={data:{data:{wrong_field:A},metadata:{version:3}}};
  await assert.rejects(f(),/vault-credential-unavailable/);
});
test('Vault refuses token file exposed to group or others',async t=>{
  const x=await remoteFixture(t);if(process.platform==='win32')return t.skip('POSIX file permission semantics not applicable');
  chmodSync(x.tokenFile,0o644);await assert.rejects(createVaultKv2SecretProvider(x.opts)(),/vault-credential-unavailable/);
});
test('Vault refuses unexpected URL schemes, remote plaintext, credentials and query strings',async t=>{
  const x=await remoteFixture(t);
  for(const baseUrl of ['http://vault.example.com','https://user:pass@vault.example.org','https://vault.example.org/?token=abc',
      'http://169.254.169.254','ftp://vault.example.org']){
    assert.throws(()=>createVaultKv2SecretProvider({...x.opts,baseUrl}),/invalid-vault-url/);
  }
  assert.throws(()=>createVaultKv2SecretProvider({...x.opts,secretPath:'../admin'}),/invalid-vault-configuration/);
  assert.throws(()=>createVaultKv2SecretProvider({...x.opts,mount:'../../secret'}),/invalid-vault-configuration/);
});
test('Vault refuses unavailable Vault instead of falling back to a stale secret',async t=>{
  const x=await remoteFixture(t);const f=createVaultKv2SecretProvider({...x.opts,fetchFn:async()=>{throw Error('network down')}});
  await assert.rejects(f(),/vault-credential-unavailable/);
});
