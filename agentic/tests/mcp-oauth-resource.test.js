import test from 'node:test';
import assert from 'node:assert/strict';
import {createPublicKey,generateKeyPairSync,sign} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {PinnedOAuthResource} from '../lib/mcp-oauth-resource.js';
import {LocalOAuthRevocations} from '../lib/oauth-revocations.js';
import {fixture,AGENT,ARGS} from '../lib/authority-fixture.js';
import {newIdentity} from '../lib/authority.js';
import {ExecutionJournal} from '../lib/pilot-receipts.js';
import {DurableSyntheticStore,createDurableSyntheticBackend} from '../lib/pilot-backend.js';
import {createSecurePilotGateway} from '../lib/pilot-mcp.js';
const now=1800000000;
const issuer='http://127.0.0.1:9400';
const resource='http://127.0.0.1:9500/mcp';
function key(){let kp=generateKeyPairSync('ed25519');return {...kp,publicJwk:{...kp.publicKey.export({format:'jwk'}),kid:'active',alg:'EdDSA',use:'sig'}};}
function token(k,{scopes='mcp:tools:read mcp:tools:execute',claims={},header={}}={}){
  const h=Buffer.from(JSON.stringify({typ:'at+jwt',alg:'EdDSA',kid:'active',...header})).toString('base64url');
  const p=Buffer.from(JSON.stringify({iss:issuer,aud:resource,sub:AGENT,client_id:'trusted-client',iat:now-10,exp:now+120,scope:scopes,...claims})).toString('base64url');
  return `${h}.${p}.${sign(null,Buffer.from(`${h}.${p}`),k.privateKey).toString('base64url')}`;
}
function config(k){return {issuer,resource,publicJwks:[k.publicJwk],allowHttpLoopback:true,clock:()=>now};}
test('OAuth resource metadata is pinned, not derived from untrusted Host',()=>{
  const k=key(),o=new PinnedOAuthResource(config(k));
  assert.equal(o.metadata.resource,resource);assert.deepEqual(o.metadata.authorization_servers,[issuer]);
  assert.ok(o.challenge().includes('http://127.0.0.1:9500/.well-known/oauth-protected-resource/mcp'));
});
test('valid EdDSA bearer scopes and client identity are verified',()=>{
  const k=key(),o=new PinnedOAuthResource(config(k));
  assert.equal(o.verifyAuthorization(`Bearer ${token(k)}`,'mcp:tools:execute').subject,AGENT);
});
test('missing token, wrong audience, wrong issuer, wrong signing key all rejected',()=>{
  const k=key(),o=new PinnedOAuthResource(config(k));
  for(const input of [null,`Bearer ${token(k,{claims:{aud:'evil'}})}`,`Bearer ${token(k,{claims:{iss:'https://bad.example'}})}`,`Bearer ${token(key())}`]){
    assert.throws(()=>o.verifyAuthorization(input,'mcp:tools:read'),/invalid_token/);
  }
});
test('expired, not-before, future issued, missing client-id and bad typ rejected',()=>{
  const k=key(),o=new PinnedOAuthResource(config(k));
  for(const claims of [{exp:now},{nbf:now+200},{iat:now+200},{client_id:''},{sub:''},{iat:now-9999}]){
    assert.throws(()=>o.verifyAuthorization(`Bearer ${token(k,{claims})}`,'mcp:tools:read'),/invalid_token/);
  }
  assert.throws(()=>o.verifyAuthorization(`Bearer ${token(k,{header:{typ:'JWT'}})}`,'mcp:tools:read'),/invalid_token/);
});
test('scope separation cannot be bypassed with a valid read-only JWT',()=>{
  const k=key(),o=new PinnedOAuthResource(config(k));
  assert.equal(o.verifyAuthorization(`Bearer ${token(k,{scopes:'mcp:tools:read'})}`,'mcp:tools:read').scope,'mcp:tools:read');
  assert.throws(()=>o.verifyAuthorization(`Bearer ${token(k,{scopes:'mcp:tools:read'})}`,'mcp:tools:execute'),e=>e.status===403);
});
test('JWK private keys, duplicate kid, wrong alg, untrusted issuer and HTTP public URL rejected',()=>{
  const k=key();
  for(const overrides of [{publicJwks:[{...k.publicJwk,d:'secret'}]},{publicJwks:[k.publicJwk,k.publicJwk]},
    {publicJwks:[{...k.publicJwk,alg:'RS256'}]},{authorizationServers:['http://127.0.0.1:9600']},{allowHttpLoopback:false}]){
    assert.throws(()=>new PinnedOAuthResource({...config(k),...overrides}));
  }
});
test('RS256 is supported with a pinned RSA JWK and exact audience',()=>{
  const kp=generateKeyPairSync('rsa',{modulusLength:2048});
  const jwk={...kp.publicKey.export({format:'jwk'}),kid:'rsa',alg:'RS256'};
  const oauth=new PinnedOAuthResource({...config(key()),publicJwks:[jwk]});
  const h=Buffer.from(JSON.stringify({typ:'at+jwt',alg:'RS256',kid:'rsa'})).toString('base64url');
  const p=Buffer.from(JSON.stringify({iss:issuer,aud:resource,sub:'machine',client_id:'client',iat:now,exp:now+90,scope:'mcp:tools:read'})).toString('base64url');
  const signature=sign('RSA-SHA256',Buffer.from(`${h}.${p}`),kp.privateKey).toString('base64url');
  assert.equal(oauth.verifyAuthorization(`Bearer ${h}.${p}.${signature}`,'mcp:tools:read').subject,'machine');
});
function rpc(method,params={},version='2026-07-28'){
  return {jsonrpc:'2.0',id:7,method,params:{...params,_meta:{'io.modelcontextprotocol/protocolVersion':version}}};
}
async function listen(t,server){await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));return `http://127.0.0.1:${server.address().port}`;}
async function setup(t,{enableRevocations=false}={}){
  const root=mkdtempSync(join(tmpdir(),'faraday-http-auth-'));t.after(()=>rmSync(root,{recursive:true,force:true}));
  const f=fixture(root),receipt=newIdentity(),backend=newIdentity(),journal=new ExecutionJournal(join(root,'journal.sqlite')),
    store=new DurableSyntheticStore(join(root,'backend.sqlite')),k=key(),
    revocationWriter=enableRevocations?new LocalOAuthRevocations(join(root,'revoked.sqlite'),{create:true}):null,
    revocationReader=enableRevocations?new LocalOAuthRevocations(join(root,'revoked.sqlite')):null,
    oauthResource=new PinnedOAuthResource({...config(k),revocations:revocationReader});
  t.after(()=>{f.close();journal.close();store.close();revocationReader?.close();revocationWriter?.close();});
  const backendServer=createDurableSyntheticBackend({secret:f.backendSecret,store,attestationPrivatePem:backend.privatePem});
  const backendUrl=await listen(t,backendServer);
  const server=createSecurePilotGateway({gate:f.gate,backendUrl:backendUrl+'/internal/execute',backendSecret:f.backendSecret,
    journal,receiptPrivatePem:receipt.privatePem,backendPublicPem:backend.publicPem,oauthResource});
  const url=await listen(t,server);return {f,url,k,store,revocationWriter,oauthResource};
}
async function post(x,method,params={},options={}){
  const version=options.version??'2026-07-28',body=rpc(method,params,version);
  const headers={'content-type':'application/json','mcp-protocol-version':version,
    'mcp-method':method,...(method==='tools/call'?{'mcp-name':params.name}:{}),
    ...(options.token===false?{}:{authorization:`Bearer ${options.token??token(x.k)}`}),...options.headers};
  if(options.faraday){headers['x-faraday-capability']=x.f.capability;headers['x-faraday-proof']=Buffer.from(JSON.stringify(x.f.proof)).toString('base64url');}
  const r=await fetch(x.url+'/mcp',{method:'POST',headers,body:JSON.stringify(body)});return {status:r.status,headers:r.headers,body:await r.json()};
}
test('resource metadata well-known is public and ignores malicious Host',async t=>{
  const x=await setup(t),r=await fetch(x.url+'/.well-known/oauth-protected-resource/mcp',{headers:{Host:'attacker.invalid'}});
  assert.equal(r.status,200);assert.equal((await r.json()).resource,resource);
});
test('OAuth rejects missing token and provides RFC9728 metadata challenge',async t=>{
  const x=await setup(t),r=await post(x,'tools/list',{}, {token:false});
  assert.equal(r.status,401);assert.match(r.headers.get('www-authenticate'),/oauth-protected-resource/);assert.equal(x.store.count(),0);
});
test('modern discover and tools/list authenticate with read-only scope',async t=>{
  const x=await setup(t),read=token(x.k,{scopes:'mcp:tools:read'});
  const a=await post(x,'server/discover',{}, {token:read});assert.equal(a.status,200);assert.deepEqual(a.body.result.supportedVersions,['2026-07-28','2025-11-25']);
  const b=await post(x,'tools/list',{}, {token:read});assert.equal(b.status,200);assert.equal(b.body.result.tools[0].name,'pay_invoice');
});
test('read-only bearer cannot elevate to execute via legacy missing mcp-method header',async t=>{
  const x=await setup(t),read=token(x.k,{scopes:'mcp:tools:read'});
  const r=await post(x,'tools/call',{name:'pay_invoice',arguments:ARGS},{token:read,faraday:true,
    version:'2025-11-25',headers:{'mcp-method':'tools/list'}});
  assert.equal(r.status,403);assert.equal(r.body.error,'insufficient_scope');assert.equal(x.store.count(),0);
});
test('bearer execute without Ed25519 authority proof cannot call backend',async t=>{
  const x=await setup(t),r=await post(x,'tools/call',{name:'pay_invoice',arguments:ARGS});
  assert.equal(r.status,403);assert.equal(x.store.count(),0);
});
test('valid bearer + authority proof executes exactly one synthetic call',async t=>{
  const x=await setup(t),r=await post(x,'tools/call',{name:'pay_invoice',arguments:ARGS},{faraday:true});
  assert.equal(r.status,200);assert.equal(r.body.result.structuredContent.status,'simulated');assert.equal(x.store.count(),1);
  assert.equal((await post(x,'tools/call',{name:'pay_invoice',arguments:ARGS},{faraday:true})).status,403);
});
test('OAuth invalid audience denies valid agent authority capability',async t=>{
  const x=await setup(t),r=await post(x,'tools/call',{name:'pay_invoice',arguments:ARGS},
    {token:token(x.k,{claims:{aud:'https://other.example/mcp'}}),faraday:true});
  assert.equal(r.status,401);assert.equal(x.store.count(),0);
});
test('modern mismatched Mcp-Method/Mcp-Name rejected before tool side effects',async t=>{
  const x=await setup(t),r=await post(x,'tools/call',{name:'pay_invoice',arguments:ARGS},
    {faraday:true,headers:{'mcp-name':'nonexistent-tool'}});
  assert.equal(r.status,400);assert.equal(x.store.count(),0);
});
test('Origin validation denies arbitrary browser origins even for valid JWT',async t=>{
  const x=await setup(t),r=await post(x,'tools/list',{}, {headers:{origin:'https://rogue.example'}});
  assert.equal(r.status,403);
});
test('non-POST /mcp cannot bypass authorization',async t=>{
  const x=await setup(t),r=await fetch(x.url+'/mcp');assert.equal(r.status,405);
});


test('OAuth subject must match FARADAY signed agent identity before forwarding',async t=>{
  const x=await setup(t),r=await post(x,'tools/call',{name:'pay_invoice',arguments:ARGS},
    {token:token(x.k,{claims:{sub:'different-agent'}}),faraday:true});
  assert.equal(r.status,403);assert.equal(x.store.count(),0);
});

test('legacy 2025 initialize and read-only catalog are supported with bearer read scope',async t=>{
  const x=await setup(t),read=token(x.k,{scopes:'mcp:tools:read'});
  const init=await post(x,'initialize',{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'sdk',version:'1'}},{token:read,version:'2025-11-25'});
  assert.equal(init.status,200);assert.equal(init.body.result.protocolVersion,'2025-11-25');
  assert.equal((await post(x,'tools/list',{}, {token:read,version:'2025-11-25'})).status,200);
});
test('modern sessionless HTTP catalog does not issue MCP session IDs',async t=>{
  const x=await setup(t),r=await post(x,'tools/list',{},{});assert.equal(r.status,200);
  assert.equal(r.headers.has('mcp-session-id'),false);assert.equal(r.body.result.resultType,'complete');
});

test('real HTTP resource gateway denies revoked token before effect, permits rotated keys',async t=>{
  const x=await setup(t,{enableRevocations:true});
  const authorized=token(x.k,{claims:{jti:'integration-token-123'}});
  assert.equal((await post(x,'tools/list',{}, {token:authorized})).status,200);
  x.revocationWriter.revoke('jti','integration-token-123');
  assert.equal((await post(x,'tools/call',{name:'pay_invoice',arguments:ARGS},{token:authorized,faraday:true})).status,401);
  assert.equal(x.store.count(),0);
  const fresh=token(x.k,{claims:{jti:'integration-token-999'}});
  assert.equal((await post(x,'tools/list',{}, {token:fresh})).status,200);
  x.revocationWriter.revoke('subject',AGENT);
  assert.equal((await post(x,'tools/list',{}, {token:fresh})).status,401);
  const newKey=key();
  x.oauthResource.replacePublicJwks([newKey.publicJwk]);
  assert.equal((await post(x,'tools/list',{}, {token:fresh})).status,401);
  // New signing key does not bypass revocation of the agent identity.
  assert.equal((await post(x,'tools/list',{}, {token:token(newKey,{claims:{jti:'new-key-token-123'}})})).status,401);
});
