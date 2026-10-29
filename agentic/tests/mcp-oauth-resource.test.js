import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import http from 'node:http';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {PinnedOAuthResource} from '../lib/mcp-oauth-resource.js';
import {fixture,AGENT,ARGS} from '../lib/authority-fixture.js';
import {newIdentity} from '../lib/authority.js';
import {ExecutionJournal} from '../lib/pilot-receipts.js';
import {DurableSyntheticStore,createDurableSyntheticBackend} from '../lib/pilot-backend.js';
import {createSecurePilotGateway} from '../lib/pilot-mcp.js';
import {createVaultKv2SecretProvider} from '../lib/vault-kv2-secret-provider.js';
import {createSignedJournalBackup,verifySignedJournalBackup,restoreVerifiedJournalBackup} from '../lib/journal-backup.js';
const now=1800000000,issuer='http://127.0.0.1:9400',resource='http://127.0.0.1:9500/mcp';
function keys(){const pair=generateKeyPairSync('ed25519');return {pair,jwk:{...pair.publicKey.export({format:'jwk'}),kid:'active',alg:'EdDSA'}};}
function token(k,claims={},head={}){const b=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
 const h=b({alg:'EdDSA',typ:'at+jwt',kid:'active',...head}),p=b({iss:issuer,aud:resource,iat:now-10,exp:now+120,sub:AGENT,client_id:'test-client',scope:'mcp:tools:read mcp:tools:execute',...claims});
 return h+'.'+p+'.'+sign(null,Buffer.from(h+'.'+p),k.pair.privateKey).toString('base64url');}
const verifier=k=>new PinnedOAuthResource({issuer,resource,publicJwks:[k.jwk],clock:()=>now,allowHttpLoopback:true});
test('public JWKS bearer check, issuer and exact audience validated',()=>{
 const k=keys(),v=verifier(k);assert.equal(v.verifyAuthorization('Bearer '+token(k),'mcp:tools:read').subject,AGENT);
 for(const bad of [{aud:'https://evil.example/mcp'},{iss:'https://evil.example'},{exp:now-1},{iat:now+1000},{client_id:''}])
 assert.throws(()=>v.verifyAuthorization('Bearer '+token(k,bad),'mcp:tools:read'),/invalid_token/);
});
test('read scope cannot execute and public JWKS cannot contain private key',()=>{
 const k=keys(),v=verifier(k);
 assert.throws(()=>v.verifyAuthorization('Bearer '+token(k,{scope:'mcp:tools:read'}),'mcp:tools:execute'),e=>e.status===403);
 assert.throws(()=>new PinnedOAuthResource({issuer,resource,allowHttpLoopback:true,publicJwks:[{...k.jwk,d:'private'}]}));
});
test('OAuth rejects invalid clocks and maximum token ages',()=>{
 const k=keys(),v=verifier(k),bearer='Bearer '+token(k);
 for(const value of [NaN,Infinity,1.5,'1800000000']){
  v.clock=()=>value;assert.throws(()=>v.verifyAuthorization(bearer,'mcp:tools:read'),/invalid_token/);
 }
 for(const maxTokenAge of [NaN,Infinity,0,-1,'3600'])
  assert.throws(()=>new PinnedOAuthResource({issuer,resource,publicJwks:[k.jwk],allowHttpLoopback:true,maxTokenAge}),/maximum age/);
});
test('JWT alg confusion and signature tampering fail closed',()=>{
 const k=keys(),v=verifier(k);
 assert.throws(()=>v.verifyAuthorization('Bearer '+token(k,{}, {alg:'none'}),'mcp:tools:read'),/invalid_token/);
 const arr=token(k).split('.');arr[2]='A'+arr[2].slice(1);if(arr[2]===token(k).split('.')[2])arr[2]='B'+arr[2].slice(1);
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
function rpc(method,params={},version='2026-07-28'){return {jsonrpc:'2.0',id:1,method,params:{...params,
 _meta:{'io.modelcontextprotocol/protocolVersion':version}}};}
async function call(x,method,params={},extra={}){
 const version=extra.version||'2026-07-28',body=rpc(method,params,version);
 const h={'content-type':'application/json','mcp-protocol-version':version,'mcp-method':method,
 ...(method==='tools/call'?{'mcp-name':params.name}:{}),
 ...(extra.noToken?{}:{authorization:'Bearer '+(extra.token||token(x.k))}),
 ...(extra.withProof?{'x-faraday-capability':x.f.capability,'x-faraday-proof':Buffer.from(JSON.stringify(x.f.proof)).toString('base64url')}:{}),...extra.headers};
 const r=await fetch(x.url+'/mcp',{method:'POST',headers:h,body:JSON.stringify(body)});
 return {status:r.status,body:await r.json(),headers:r.headers};
}
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
 {withProof:true,version:'2025-11-25',token:token(x.k,{scope:'mcp:tools:read'}),headers:{'mcp-method':'tools/list'}});
 assert.equal(r.status,403);assert.equal(x.store.count(),0);
});
test('bearer alone and capability alone are each insufficient',async t=>{
 const x=await system(t),params={name:'pay_invoice',arguments:ARGS};
 assert.equal((await call(x,'tools/call',params)).status,403);
 assert.equal((await call(x,'tools/call',params,{withProof:true,token:token(x.k,{aud:'https://evil.example/mcp'})})).status,401);
 assert.equal(x.store.count(),0);
});
test('OAuth subject must bind to signed FARADAY agent identity',async t=>{
 const x=await system(t),params={name:'pay_invoice',arguments:ARGS},r=await call(x,'tools/call',params,{withProof:true,token:token(x.k,{sub:'rogue-agent'})});
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
 assert.equal((await call(x,'tools/call',params,{withProof:true,token:token(x.k,{aud:'https://wrong.example/mcp'})})).status,401);
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
