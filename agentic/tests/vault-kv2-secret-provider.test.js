import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
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