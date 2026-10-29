import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import http from 'node:http';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {PinnedOAuthResource} from '../lib/mcp-oauth-resource.js';
import {LocalOAuthRevocations} from '../lib/oauth-revocations.js';
import {fixture,AGENT,ARGS} from '../lib/authority-fixture.js';
import {newIdentity} from '../lib/authority.js';
import {ExecutionJournal} from '../lib/pilot-receipts.js';
import {DurableSyntheticStore,createDurableSyntheticBackend} from '../lib/pilot-backend.js';
import {createSecurePilotGateway} from '../lib/pilot-mcp.js';
import {createVaultKv2SecretProvider} from '../lib/vault-kv2-secret-provider.js';
import {createSignedJournalBackup,verifySignedJournalBackup,restoreVerifiedJournalBackup} from '../lib/journal-backup.js';
const now=1800000000,issuer='http://127.0.0.1:9400',resource='http://127.0.0.1:9500/mcp';
function keys(){const pair=generateKeyPairSync('ed25519');return {pair,jwk:{...pair.publicKey.export({format:'jwk'}),kid:'active',alg:'EdDSA'}};}
function localToken(k,claims={},head={}){const b=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
 const h=b({alg:'EdDSA',typ:'at+jwt',kid:'active',...head}),p=b({iss:issuer,aud:resource,iat:now-10,exp:now+120,sub:AGENT,client_id:'test-client',scope:'mcp:tools:read mcp:tools:execute',...claims});
 return h+'.'+p+'.'+sign(null,Buffer.from(h+'.'+p),k.pair.privateKey).toString('base64url');}
const verifier=k=>new PinnedOAuthResource({issuer,resource,publicJwks:[k.jwk],clock:()=>now,allowHttpLoopback:true});
test('public JWKS bearer check, issuer and exact audience validated',()=>{
 const k=keys(),v=verifier(k);assert.equal(v.verifyAuthorization('Bearer '+localToken(k),'mcp:tools:read').subject,AGENT);
 for(const bad of [{aud:'https://evil.example/mcp'},{iss:'https://evil.example'},{exp:now-1},{iat:now+1000},{client_id:''}])
 assert.throws(()=>v.verifyAuthorization('Bearer '+localToken(k,bad),'mcp:tools:read'),/invalid_token/);
});
test('read scope cannot execute and public JWKS cannot contain private key',()=>{
 const k=keys(),v=verifier(k);
 assert.throws(()=>v.verifyAuthorization('Bearer '+localToken(k,{scope:'mcp:tools:read'}),'mcp:tools:execute'),e=>e.status===403);
 assert.throws(()=>new PinnedOAuthResource({issuer,resource,allowHttpLoopback:true,publicJwks:[{...k.jwk,d:'private'}]}));
});
test('OAuth rejects invalid clocks and maximum token ages',()=>{
 const k=keys(),v=verifier(k),bearer='Bearer '+localToken(k);
 for(const value of [NaN,Infinity,1.5,'1800000000']){
  v.clock=()=>value;assert.throws(()=>v.verifyAuthorization(bearer,'mcp:tools:read'),/invalid_token/);
 }
 for(const maxTokenAge of [NaN,Infinity,0,-1,'3600'])
  assert.throws(()=>new PinnedOAuthResource({issuer,resource,publicJwks:[k.jwk],allowHttpLoopback:true,maxTokenAge}),/maximum age/);
});
test('JWT alg confusion and signature tampering fail closed',()=>{
 const k=keys(),v=verifier(k);
 assert.throws(()=>v.verifyAuthorization('Bearer '+localToken(k,{}, {alg:'none'}),'mcp:tools:read'),/invalid_token/);
 const arr=localToken(k).split('.');arr[2]='A'+arr[2].slice(1);if(arr[2]===localToken(k).split('.')[2])arr[2]='B'+arr[2].slice(1);
 assert.throws(()=>v.verifyAuthorization('Bearer '+arr.join('.'),'mcp:tools:read'),/invalid_token/);
});
async function serve(t,s){await new Promise(resolve=>s.listen(0,'127.0.0.1',resolve));(t._faradayServers??=[]).push(s);return 'http://127.0.0.1:'+s.address().port;}
async function system(t,options={}){
 const dir=mkdtempSync(join(tmpdir(),'faraday-http-oauth-'));
 const f=fixture(dir),receipt=newIdentity(),backKey=newIdentity(),journal=new ExecutionJournal(join(dir,'journal.sqlite')),
 store=new DurableSyntheticStore(join(dir,'backend.sqlite')),k=keys();
 
 const backend=createDurableSyntheticBackend({secret:f.backendSecret,store,attestationPrivatePem:backKey.privatePem});
 const backendUrl=await serve(t,backend);
 const g=createSecurePilotGateway({gate:f.gate,backendUrl:backendUrl+'/internal/execute',backendSecret:f.backendSecret,
 journal,receiptPrivatePem:receipt.privatePem,backendPublicPem:backKey.publicPem,oauthResource:verifier(k),...options});
 const url=await serve(t,g);
 t.after(async()=>{
   for(const server of [...t._faradayServers].reverse()){
     await new Promise(resolve=>{server.close(resolve);server.closeAllConnections();});
   }
   f.close();journal.close();store.close();rmSync(dir,{recursive:true,force:true});
 });
 return {url,f,store,k,journal,dir};
}
async function call(x,method,params={},options={}){
 const version=options.version??'2026-07-28';
 const headers={'content-type':'application/json','mcp-protocol-version':version,'mcp-method':method,
  ...(method==='tools/call'?{'mcp-name':params.name}:{}),...(options.noToken?{}:{authorization:'Bearer '+(options.token??localToken(x.k))}),...options.headers};
 if(options.withProof){headers['x-faraday-capability']=x.f.capability;headers['x-faraday-proof']=Buffer.from(JSON.stringify(x.f.proof)).toString('base64url');}
 const response=await fetch(x.url+'/mcp',{method:'POST',headers,body:JSON.stringify(rpc(method,params,version))});
 return {status:response.status,body:await response.json(),headers:response.headers};
}
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
async function listen(t,server){await new Promise(r=>server.listen(0,'127.0.0.1',r));return `http://127.0.0.1:${server.address().port}`;}
async function setup(t,{enableRevocations=false,...gatewayOptions}={}){
  const root=mkdtempSync(join(tmpdir(),'faraday-http-auth-'));
  const f=fixture(root),receipt=newIdentity(),backend=newIdentity(),journal=new ExecutionJournal(join(root,'journal.sqlite')),
    store=new DurableSyntheticStore(join(root,'backend.sqlite')),k=key(),
    revocationWriter=enableRevocations?new LocalOAuthRevocations(join(root,'revoked.sqlite'),{create:true}):null,
    revocationReader=enableRevocations?new LocalOAuthRevocations(join(root,'revoked.sqlite')):null,
    oauthResource=new PinnedOAuthResource({...config(k),revocations:revocationReader});
  const backendServer=createDurableSyntheticBackend({secret:f.backendSecret,store,attestationPrivatePem:backend.privatePem});
  const backendUrl=await listen(t,backendServer);
  const server=createSecurePilotGateway({gate:f.gate,backendUrl:backendUrl+'/internal/execute',backendSecret:f.backendSecret,
    journal,receiptPrivatePem:receipt.privatePem,backendPublicPem:backend.publicPem,oauthResource,...gatewayOptions});
  const url=await listen(t,server);
  t.after(async()=>{
    for(const running of [server,backendServer])await new Promise(resolve=>{running.close(resolve);running.closeAllConnections();});
    f.close();journal.close();store.close();revocationReader?.close();revocationWriter?.close();rmSync(root,{recursive:true,force:true});
  });
  return {f,url,k,store,revocationWriter,oauthResource};
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
test('RFC 9728 resource metadata is not derived from Host',async t=>{
 const x=await system(t),r=await fetch(x.url+'/.well-known/oauth-protected-resource/mcp',{headers:{Host:'evil.invalid'}});
 assert.equal(r.status,200);assert.equal((await r.json()).resource,resource);
});
test('OAuth challenge and modern 2026 discovery/list tools are valid JSON envelopes',async t=>{
 const x=await system(t);const bad=await call(x,'tools/list',{}, {noToken:true});
 assert.equal(bad.status,401);assert.match(bad.headers.get('www-authenticate'),/oauth-protected-resource/);
 const disc=await call(x,'server/discover');assert.equal(disc.status,200);assert.deepEqual(disc.body.result.supportedVersions,['2026-07-28','2025-11-25']);
 const list=await call(x,'tools/list');assert.equal(list.status,200);assert.equal(list.body.result.resultType,'complete');
});
test('header/body confusion on 2025 legacy cannot elevate read-only scope',async t=>{
 const x=await system(t),r=await call(x,'tools/call',{name:'pay_invoice',arguments:ARGS},
 {withProof:true,version:'2025-11-25',token:localToken(x.k,{scope:'mcp:tools:read'}),headers:{'mcp-method':'tools/list'}});
 assert.equal(r.status,403);assert.equal(x.store.count(),0);
});
test('bearer alone and capability alone are each insufficient',async t=>{
 const x=await system(t),params={name:'pay_invoice',arguments:ARGS};
 assert.equal((await call(x,'tools/call',params)).status,403);
 assert.equal((await call(x,'tools/call',params,{withProof:true,token:localToken(x.k,{aud:'https://evil.example/mcp'})})).status,401);
 assert.equal(x.store.count(),0);
});
test('OAuth subject must bind to signed FARADAY agent identity',async t=>{
 const x=await system(t),params={name:'pay_invoice',arguments:ARGS},r=await call(x,'tools/call',params,{withProof:true,token:localToken(x.k,{sub:'rogue-agent'})});
 assert.equal(r.status,403);assert.equal(x.store.count(),0);
 assert.equal((await call(x,'tools/call',params,{withProof:true})).status,200);assert.equal(x.store.count(),1);
});
test('fully authorized synthetic tool executes once, replay blocked',async t=>{
 const x=await system(t),params={name:'pay_invoice',arguments:ARGS};
 const ok=await call(x,'tools/call',params,{withProof:true});assert.equal(ok.status,200);
 assert.equal(ok.body.result.resultType,'complete');assert.equal(x.store.count(),1);
 assert.equal((await call(x,'tools/call',params,{withProof:true})).status,403);assert.equal(x.store.count(),1);
});
test('E31 synthetic OAuth, secret outage, gateway events and signed backup work together',async t=>{
 const tokenDir=mkdtempSync(join(tmpdir(),'faraday-reference-secret-')),tokenFile=join(tokenDir,'token');
 t.after(()=>rmSync(tokenDir,{recursive:true,force:true}));
 writeFileSync(tokenFile,'fixture-token-1234567890',{mode:0o600});
 let enabled=false,secret,requests=0;
 const vault=await serve(t,http.createServer((request,response)=>{
  requests++;
  if(!enabled||request.headers['x-vault-token']!=='fixture-token-1234567890'){response.writeHead(403);response.end();return;}
  response.writeHead(200,{'content-type':'application/json'});
  response.end(JSON.stringify({data:{data:{backend_credential:secret},metadata:{version:1}}}));
 }));
 const provider=createVaultKv2SecretProvider({baseUrl:vault,secretPath:'gateway/backend',tokenFile,allowLoopbackHttp:true});
 const events=[],x=await system(t,{backendSecret:undefined,backendSecretProvider:provider,onEvent:event=>events.push(event)});
 secret=x.f.backendSecret;
 const params={name:'pay_invoice',arguments:ARGS};
 assert.equal((await call(x,'tools/call',params,{withProof:true,token:localToken(x.k,{aud:'https://wrong.example/mcp'})})).status,401);
 assert.equal(requests,0);assert.equal(x.store.count(),0);
 assert.equal((await call(x,'tools/call',params,{withProof:true})).status,503);assert.equal(x.store.count(),0);
 assert.equal(x.f.gatewayLedger.db.prepare('SELECT count(*) AS n FROM consumed').get().n,0);
 enabled=true;assert.equal((await call(x,'tools/call',params,{withProof:true})).status,200);
 assert.equal((await call(x,'tools/call',params,{withProof:true})).status,403);assert.equal(x.store.count(),1);
 assert.ok(events.some(event=>event.status==='simulated'));assert.ok(!JSON.stringify(events).includes(secret));
 const key=newIdentity(),backupPath=join(x.dir,'backup.sqlite'),restorePath=join(x.dir,'restored.sqlite');
 const backup=await createSignedJournalBackup({journalPath:join(x.dir,'journal.sqlite'),backupPath,privatePem:key.privatePem});
 assert.equal(verifySignedJournalBackup({backupPath,publicPem:key.publicPem,expectedSha256:backup.backupSha256}).operationCount,1);
 assert.equal(restoreVerifiedJournalBackup({backupPath,restorePath,publicPem:key.publicPem}).executionRepeated,false);
 const restored=new ExecutionJournal(restorePath);try{assert.equal(restored.db.prepare('SELECT count(*) AS n FROM executions').get().n,1);}finally{restored.close();}
 assert.equal(x.store.count(),1);
});
test('modern Mcp-Name header mismatch denies before side effect',async t=>{
 const x=await system(t);assert.equal((await call(x,'tools/call',{name:'pay_invoice',arguments:ARGS},
 {withProof:true,headers:{'mcp-name':'other'}})).status,400);assert.equal(x.store.count(),0);
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
test('OAuth revocation during credential lookup denies the pending call before its effect',async t=>{
 let release,notify;const started=new Promise(resolve=>{notify=resolve;});let x;
 x=await setup(t,{enableRevocations:true,backendSecret:undefined,backendSecretProvider:()=>new Promise(resolve=>{release=()=>resolve(x.f.backendSecret);notify();})});
 const authorized=token(x.k,{claims:{jti:'pending-token-123'}});
 const pending=post(x,'tools/call',{name:'pay_invoice',arguments:ARGS},{token:authorized,faraday:true});
 await started;x.revocationWriter.revoke('jti','pending-token-123');release();
 assert.equal((await pending).status,403);assert.equal(x.store.count(),0);
 assert.equal(x.f.gatewayLedger.db.prepare('SELECT count(*) AS n FROM consumed').get().n,0);
});
