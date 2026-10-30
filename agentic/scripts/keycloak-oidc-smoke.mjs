#!/usr/bin/env node
/** R5 real HTTPS Keycloak issuer smoke. Tests issuer-signed bearer tokens.
 * Disposable CI-only realm; no production SSO onboarding claim.
 */
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {mkdirSync,writeFileSync,readFileSync,mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {fixture,AGENT,ARGS} from '../lib/authority-fixture.js';
import {newIdentity} from '../lib/authority.js';
import {ExecutionJournal,verifyReceipt} from '../lib/pilot-receipts.js';
import {DurableSyntheticStore,createDurableSyntheticBackend} from '../lib/pilot-backend.js';
import {createSecurePilotGateway} from '../lib/pilot-mcp.js';
import {join,resolve} from 'node:path';
import {PinnedOAuthResource} from '../lib/mcp-oauth-resource.js';
const root=resolve(process.argv[3]||'.');
const issuer='https://127.0.0.1:18443/realms/faraday-r5';
const resource='https://gateway.example.test/mcp';
const scope='mcp:tools:read mcp:tools:execute';
const fmt=secret=>({
 clientId:secret.id,enabled:true,protocol:'openid-connect',publicClient:false,
 clientAuthenticatorType:'client-secret',secret:secret.value,serviceAccountsEnabled:true,
 standardFlowEnabled:false,directAccessGrantsEnabled:false,fullScopeAllowed:false,
 defaultClientScopes:['mcp:tools:read','mcp:tools:execute'],
 protocolMappers:[{name:'faraday-gateway-audience',protocol:'openid-connect',protocolMapper:'oidc-audience-mapper',
 config:{'included.custom.audience':resource,'access.token.claim':'true','id.token.claim':'false'}}]
});
if(process.argv[2]==='prepare'){
 const importDir=join(root,'import');mkdirSync(importDir,{recursive:true,mode:0o755});
 const allowed={id:'faraday-r5',value:randomBytes(32).toString('hex')};
 const rogue={id:'rogue-r5',value:randomBytes(32).toString('hex')};
 const custom=name=>({name,protocol:'openid-connect',attributes:{'include.in.token.scope':'true','display.on.consent.screen':'false'}});
 const realm={realm:'faraday-r5',enabled:true,accessTokenLifespan:300,
  clientScopes:[custom('mcp:tools:read'),custom('mcp:tools:execute')],
  clients:[fmt(allowed),fmt(rogue)]};
 writeFileSync(join(importDir,'faraday-r5-realm.json'),JSON.stringify(realm),{mode:0o644,flag:'wx'});
 writeFileSync(join(root,'client-secrets.json'),JSON.stringify({allowed,rogue}),{mode:0o600,flag:'wx'});
 console.log(JSON.stringify({kind:'faraday-oidc-fixture-prepared',mode:'ephemeral',credentialContentsLogged:false}));
}else if(process.argv[2]==='verify'){
 const creds=JSON.parse(readFileSync(join(root,'client-secrets.json'),'utf8'));
 const metadata=issuer+'/.well-known/openid-configuration';
 let doc;
 for(let attempt=0;attempt<80;attempt++){
  try{const r=await fetch(metadata,{signal:AbortSignal.timeout(2500),redirect:'error'});
   if(r.ok){doc=await r.json();break;}}catch{}
  await new Promise(resolve=>setTimeout(resolve,2000));
 }
 assert.ok(doc,'Keycloak OIDC discovery unavailable over verified HTTPS');
 assert.equal(doc.issuer,issuer);
 assert.equal(doc.token_endpoint,issuer+'/protocol/openid-connect/token');
 assert.equal(doc.jwks_uri,issuer+'/protocol/openid-connect/certs');
 const jwksResponse=await fetch(doc.jwks_uri,{signal:AbortSignal.timeout(5000),redirect:'error'});
 assert.equal(jwksResponse.status,200);
 const keys=(await jwksResponse.json()).keys;
 assert.ok(Array.isArray(keys)&&keys.length>0);
 async function mint(client){
  const body=new URLSearchParams({grant_type:'client_credentials',client_id:client.id,client_secret:client.value,scope});
  const r=await fetch(doc.token_endpoint,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},
   body,redirect:'error',signal:AbortSignal.timeout(10000)});
  assert.equal(r.status,200,'Keycloak client-credentials grant failed');
  const response=await r.json();
  assert.equal(response.token_type.toLowerCase(),'bearer');
  assert.equal(response.access_token.split('.').length,3);
  return response.access_token;
 }
 const good=await mint(creds.allowed),rogue=await mint(creds.rogue);
 const header=JSON.parse(Buffer.from(good.split('.')[0],'base64url').toString('utf8'));
 const publicJwk=keys.find(k=>k.kid===header.kid);
 assert.ok(publicJwk&&publicJwk.kty==='RSA','No RSA signing key for current Keycloak token');
 const resourceServer=new PinnedOAuthResource({issuer,resource,publicJwks:[publicJwk],
  tokenProfile:'keycloak-oidc',allowedClientIds:['faraday-r5']});
 const identity=resourceServer.verifyAuthorization('Bearer '+good,'mcp:tools:read');
 assert.equal(identity.clientId,'faraday-r5');
 resourceServer.verifyAuthorization('Bearer '+good,'mcp:tools:execute');
 assert.throws(()=>resourceServer.verifyAuthorization('Bearer '+rogue,'mcp:tools:read'),/invalid_token/);
 const bad=good.split('.');bad[2]=(bad[2][0]==='A'?'B':'A')+bad[2].slice(1);
 assert.throws(()=>resourceServer.verifyAuthorization('Bearer '+bad.join('.'),'mcp:tools:read'),/invalid_token/);
 const revocations={isRevoked:({subject})=>subject===identity.subject};
 const revoked=new PinnedOAuthResource({issuer,resource,publicJwks:[publicJwk],
  tokenProfile:'keycloak-oidc',allowedClientIds:['faraday-r5'],revocations});
 assert.throws(()=>revoked.verifyAuthorization('Bearer '+good,'mcp:tools:read'),/invalid_token/);
 // Exercise the real HTTP MCP gateway using bearer JWTs minted by Keycloak.
 // No backend socket is created: tools/list may succeed, tools/call without an
 // independently signed FARADAY authority proof MUST remain denied.
 const work=mkdtempSync(join(root,'keycloak-mcp-gateway-'));
 const f=fixture(work),journal=new ExecutionJournal(join(work,'journal.sqlite'));
 const receiptKey=newIdentity(),backendKey=newIdentity();
 const store=new DurableSyntheticStore(join(work,'backend.sqlite'));
 const backend=createDurableSyntheticBackend({secret:f.backendSecret,store,attestationPrivatePem:backendKey.privatePem});
 await new Promise(resolve=>backend.listen(0,'127.0.0.1',resolve));
 const backendUrl='http://127.0.0.1:'+backend.address().port+'/internal/execute';
 const gateway=createSecurePilotGateway({gate:f.gate,
  backendUrl,allowInsecureBackend:true,oauthClientAgentBindings:{'faraday-r5':AGENT},
  backendSecret:f.backendSecret,journal,receiptPrivatePem:receiptKey.privatePem,
  backendPublicPem:backendKey.publicPem,oauthResource:resourceServer});
 try{
  await new Promise(resolve=>gateway.listen(0,'127.0.0.1',resolve));
  const gatewayUrl='http://127.0.0.1:'+gateway.address().port+'/mcp';
  const ask=async(token,method,params,extra={})=>{
   const r=await fetch(gatewayUrl,{method:'POST',headers:{'content-type':'application/json',
    'mcp-protocol-version':'2026-07-28','mcp-method':method,
    ...(method==='tools/call'?{'mcp-name':'pay_invoice'}:{}),
    ...(token?{authorization:'Bearer '+token}:{}),...extra},
    body:JSON.stringify({jsonrpc:'2.0',id:1,method,
     params:{...params,_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28'}}})});
   await r.body?.cancel();
   return r.status;
  };
  assert.equal(await ask(good,'tools/list',{}),200);
  assert.equal(await ask(rogue,'tools/list',{}),401);
  assert.equal(await ask(null,'tools/list',{}),401);
  assert.equal(await ask(good,'tools/call',{name:'pay_invoice',
   arguments:{amount_cents:100,currency:'EUR',recipient:'supplier_demo'}}),403);
  const authorityHeaders={'x-faraday-capability':f.capability,
   'x-faraday-proof':Buffer.from(JSON.stringify(f.proof)).toString('base64url')};
  assert.equal(await ask(rogue,'tools/call',{name:'pay_invoice',arguments:ARGS},authorityHeaders),401);
  assert.equal(await ask(good,'tools/call',{name:'pay_invoice',arguments:{...ARGS,amount_cents:100}},authorityHeaders),403);
  assert.equal(store.count(),0);
  assert.equal(await ask(good,'tools/call',{name:'pay_invoice',arguments:ARGS},authorityHeaders),200);
  assert.equal(store.count(),1);
  const id=f.proof.payload.jti;
  const recorded=journal.get(id);
  assert.equal(recorded?.state,'simulated');
  assert.equal(verifyReceipt({publicPem:receiptKey.publicPem,backendPublicPem:backendKey.publicPem,
   receipt:recorded.receipt}).backendVerified,true);
  assert.equal(await ask(good,'tools/call',{name:'pay_invoice',arguments:ARGS},authorityHeaders),403);
  assert.equal(store.count(),1);
  // A valid provider token is insufficient to bypass the backend's independent credential.
  const unauth=await fetch(backendUrl,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({})});
  assert.equal(unauth.status,401);await unauth.body?.cancel();
 }finally{
  gateway.closeAllConnections();
  await new Promise(resolve=>gateway.close(resolve));
  backend.closeAllConnections();await new Promise(resolve=>backend.close(resolve));
  journal.close();store.close();f.close();rmSync(work,{recursive:true,force:true});
 }
 console.log(JSON.stringify({kind:'faraday-r5-real-https-oidc',result:'pass',
  controls:['TLS-validated-OIDC-discovery','provider-issued-RS256-token','pinned-JWKS',
    'exact-resource-audience','read-scope','execute-scope','authorized-client-only',
    'forged-signature-denied','local-revocation-denied',
    'real-http-mcp-list-allowed','rogue-client-gateway-denied','missing-bearer-gateway-denied',
    'bearer-without-authority-proof-denied','provider-issued-jwt-signed-agent-proof-executes',
    'independent-signed-backend-attestation','receipt-independently-verified',
    'argument-tampering-denied','capability-replay-denied','direct-backend-without-credential-denied'],
  issuerType:'official-keycloak',clientCredentialsFrom:'runtime-generated-CI-fixture',
  limitations:['Keycloak development-mode only','test-only certificate and realm',
    'no production SSO, token exchange or agent delegation attestation',
    'real MCP synthetic execution with issuer-signed machine identity and operator-mapped agent, not token exchange or user delegation',
    'no production gateway deployment, Vault in this same runtime, or enterprise R2 acceptance']}));
}else{throw Error('usage: keycloak-oidc-smoke.mjs prepare|verify ROOT');}
