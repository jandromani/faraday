#!/usr/bin/env node
/** R5 real HTTPS Keycloak issuer smoke. Tests issuer-signed bearer tokens.
 * Disposable CI-only realm; no production SSO onboarding claim.
 */
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {mkdirSync,writeFileSync,readFileSync,mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {fixture,AGENT,ARGS,TOOL,RESOURCE,ACTION} from '../lib/authority-fixture.js';
import {newIdentity,createIntent,createExecution} from '../lib/authority.js';
import {createVerifiedOidcDelegation} from '../lib/oidc-delegation-binding.js';
import {delegateNarrower} from '../lib/delegation-chain.js';
import {ExecutionJournal,verifyReceipt} from '../lib/pilot-receipts.js';
import {DurableSyntheticStore,createDurableSyntheticBackend} from '../lib/pilot-backend.js';
import {createVaultKv2SecretProvider} from '../lib/vault-kv2-secret-provider.js';
import {createSecurePilotGateway} from '../lib/pilot-mcp.js';
import {join,resolve} from 'node:path';
import {PinnedOAuthResource} from '../lib/mcp-oauth-resource.js';
const root=resolve(process.argv[3]||'.');
const issuer='https://127.0.0.1:18443/realms/faraday-r5';
const resource='https://gateway.example.test/mcp';
const scope='mcp:tools:read mcp:tools:execute';
/** Official Vault dev bootstrap; only the scoped AppRole token is passed to the gateway. */
async function prepareScopedVault({credential,dir}){
 const baseUrl='http://127.0.0.1:18200',rootToken=process.env.FARADAY_TEST_VAULT_TOKEN;
 assert.ok(typeof rootToken==='string'&&rootToken.length>=12,'R6 requires disposable Vault bootstrap');
 const api=async(path,{method='GET',token=rootToken,body,expect=[200,204]}={})=>{
  const r=await fetch(baseUrl+path,{method,headers:{'x-vault-token':token,
   'content-type':'application/json',accept:'application/json'},
   body:body===undefined?undefined:JSON.stringify(body),redirect:'error',
   signal:AbortSignal.timeout(5000)});
  assert.ok(expect.includes(r.status),'Vault bootstrap/revocation failed');
  if(r.status===204){await r.body?.cancel();return {};}
  return r.json();
 };
 let ready=false;
 for(let i=0;i<35;i++){
  try{const r=await fetch(baseUrl+'/v1/sys/health',{signal:AbortSignal.timeout(1500)});
   if(r.ok){ready=true;await r.body?.cancel();break;}}catch{}
  await new Promise(resolve=>setTimeout(resolve,300));
 }
 assert.ok(ready,'Vault not ready for combined R6 scenario');
 await api('/v1/sys/policies/acl/r6-mcp-gateway',{method:'PUT',
  body:{policy:'path "secret/data/gateway/backend" { capabilities = ["read"] }'}});
 await api('/v1/sys/auth/approle',{method:'POST',body:{type:'approle'}});
 await api('/v1/auth/approle/role/r6-mcp-gateway',{method:'POST',
  body:{token_policies:['r6-mcp-gateway'],token_no_default_policy:true,
   token_ttl:'90s',token_max_ttl:'180s',secret_id_num_uses:1,token_num_uses:0}});
 const roleId=(await api('/v1/auth/approle/role/r6-mcp-gateway/role-id')).data.role_id;
 assert.ok(typeof roleId==='string'&&roleId.length>10);
 await api('/v1/secret/data/gateway/backend',{method:'POST',
  body:{data:{backend_credential:credential}}});
 const tokenFile=join(dir,'vault-scoped-token'),scoped=[];
 const renew=async()=>{
  const secretId=(await api('/v1/auth/approle/role/r6-mcp-gateway/secret-id',{method:'POST',body:{}})).data.secret_id;
  const login=await api('/v1/auth/approle/login',{method:'POST',body:{role_id:roleId,secret_id:secretId}});
  const token=login.auth.client_token;
  assert.ok(typeof token==='string'&&token.length>10&&token!==rootToken);
  scoped.push(token);writeFileSync(tokenFile,token,{mode:0o600});
 };
 await renew();
 const provider=createVaultKv2SecretProvider({baseUrl,mount:'secret',
  secretPath:'gateway/backend',tokenFile,allowLoopbackHttp:true});
 assert.equal(await provider(),credential);
 await api('/v1/secret/data/other/backend',{token:scoped.at(-1),expect:[403]});
 return {provider,renew,revoke:()=>api('/v1/auth/token/revoke',{method:'POST',
    body:{token:scoped.at(-1)}})};
}
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
 const human={id:'faraday-human-lab',value:randomBytes(32).toString('hex'),username:'r19-operator',password:randomBytes(32).toString('hex')};
 const custom=name=>({name,protocol:'openid-connect',attributes:{'include.in.token.scope':'true','display.on.consent.screen':'false'}});
 const realm={realm:'faraday-r5',enabled:true,accessTokenLifespan:300,
  clientScopes:[custom('mcp:tools:read'),custom('mcp:tools:execute'),custom('faraday:delegate')],
  clients:[fmt(allowed),fmt(rogue),{...fmt(human),serviceAccountsEnabled:false,
   directAccessGrantsEnabled:true,defaultClientScopes:['mcp:tools:read','mcp:tools:execute','faraday:delegate']}],
  users:[{username:human.username,enabled:true,emailVerified:true,
   firstName:'CI',lastName:'Operator',requiredActions:[],
   credentials:[{type:'password',value:human.password,temporary:false}]}]};
 writeFileSync(join(importDir,'faraday-r5-realm.json'),JSON.stringify(realm),{mode:0o644,flag:'wx'});
 writeFileSync(join(root,'client-secrets.json'),JSON.stringify({allowed,rogue,human}),{mode:0o600,flag:'wx'});
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
 const humanResponse=await fetch(doc.token_endpoint,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},
  body:new URLSearchParams({grant_type:'password',client_id:creds.human.id,
   client_secret:creds.human.value,username:creds.human.username,password:creds.human.password,
   scope:'mcp:tools:execute faraday:delegate'}),redirect:'error',signal:AbortSignal.timeout(10000)});
 assert.equal(humanResponse.status,200,'test-only Keycloak user token issue failed');
 const humanBearer=(await humanResponse.json()).access_token;
 assert.equal(humanBearer.split('.').length,3);
 const header=JSON.parse(Buffer.from(good.split('.')[0],'base64url').toString('utf8'));
 const publicJwk=keys.find(k=>k.kid===header.kid);
 assert.ok(publicJwk&&publicJwk.kty==='RSA','No RSA signing key for current Keycloak token');
 const resourceServer=new PinnedOAuthResource({issuer,resource,publicJwks:[publicJwk],
  tokenProfile:'keycloak-oidc',allowedClientIds:['faraday-r5']});
 const humanResource=new PinnedOAuthResource({issuer,resource,publicJwks:[publicJwk],
  tokenProfile:'keycloak-oidc',allowedClientIds:['faraday-human-lab']});
 const humanIdentity=humanResource.verifyAuthorization('Bearer '+humanBearer,'faraday:delegate');
 assert.equal(humanIdentity.clientId,'faraday-human-lab');
 assert.ok(humanIdentity.subject&&!humanIdentity.subject.startsWith('service-account-'));
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
 const approle=await prepareScopedVault({credential:f.backendSecret,dir:work});
 const store=new DurableSyntheticStore(join(work,'backend.sqlite'));
 const backend=createDurableSyntheticBackend({secret:f.backendSecret,store,attestationPrivatePem:backendKey.privatePem});
 await new Promise(resolve=>backend.listen(0,'127.0.0.1',resolve));
 const backendUrl='http://127.0.0.1:'+backend.address().port+'/internal/execute';
 const gateway=createSecurePilotGateway({gate:f.gate,
  backendUrl,allowInsecureBackend:true,oauthClientAgentBindings:{'faraday-r5':AGENT},
  backendSecretProvider:approle.provider,journal,receiptPrivatePem:receiptKey.privatePem,
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
  const id=JSON.parse(Buffer.from(f.capability,'base64url').toString('utf8')).payload.jti;
  const recorded=journal.get(id);
  assert.equal(recorded?.state,'simulated');
  assert.equal(verifyReceipt({publicPem:receiptKey.publicPem,backendPublicPem:backendKey.publicPem,
   receipt:recorded.receipt}).backendVerified,true);
  assert.equal(await ask(good,'tools/call',{name:'pay_invoice',arguments:ARGS},authorityHeaders),403);
  assert.equal(store.count(),1);
  // Revoke the live AppRole before Authority spends another capability.
  const timestamp=Math.floor(Date.now()/1000);
  const intent=createIntent({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,
   agentPrivatePem:f.agent.privatePem,now:timestamp});
  const nextCapability=f.iss.issue(intent);
  const nextProof=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,
   capability:nextCapability,agentPrivatePem:f.agent.privatePem,now:timestamp});
  const renewalHeaders={'x-faraday-capability':nextCapability,
   'x-faraday-proof':Buffer.from(JSON.stringify(nextProof)).toString('base64url')};
  await approle.revoke();
  assert.equal(await ask(good,'tools/call',{name:'pay_invoice',arguments:ARGS},renewalHeaders),503);
  assert.equal(store.count(),1,'revoked Vault token must prevent backend effect');
  await approle.renew();
  assert.equal(await ask(good,'tools/call',{name:'pay_invoice',arguments:ARGS},renewalHeaders),200);
  assert.equal(store.count(),2);
  // Keycloak real test-user JWT is verified at GRANT issuance and at every
  // delegated tool execution, not used to impersonate an agent directly.
  const operatorKey=newIdentity();
  let humanRevoked=false;
  const delegated=createVerifiedOidcDelegation({
   oauthResource:humanResource,issuerPrivatePem:operatorKey.privatePem,
   issuerPublicPem:operatorKey.publicPem,allowedUserClients:['faraday-human-lab'],
   authorizeSubject:({subject,clientId})=>!humanRevoked&&subject===humanIdentity.subject&&clientId==='faraday-human-lab',
   agentPublicKeys:{[AGENT]:f.agent.publicPem},revoked:()=>false});
  const rootGrant=delegated.issue({authorizationHeader:'Bearer '+humanBearer,
   agent:AGENT,scope:{tool:TOOL,resource:RESOURCE,action:ACTION,maxAmountCents:ARGS.amount_cents}});
  assert.equal(delegated.verify({authorizationHeader:'Bearer '+humanBearer,chain:[rootGrant],
   expected:{agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,
    amountCents:ARGS.amount_cents}}).agent,AGENT);
  const child='faraday://r19/child';
  const childGrant=delegateNarrower({fromAgent:AGENT,toAgent:child,
   fromPrivatePem:f.agent.privatePem,parent:rootGrant,
   maxAmountCents:Math.max(1,Math.floor(ARGS.amount_cents/2))});
  delegated.verify({authorizationHeader:'Bearer '+humanBearer,chain:[rootGrant,childGrant],
   expected:{agent:child,tool:TOOL,resource:RESOURCE,action:ACTION,
    amountCents:Math.max(1,Math.floor(ARGS.amount_cents/2))}});
  assert.throws(()=>delegated.verify({authorizationHeader:'Bearer '+humanBearer,
   chain:[rootGrant,childGrant],expected:{agent:child,tool:TOOL,resource:RESOURCE,
    action:ACTION,amountCents:ARGS.amount_cents+1}}),/delegation-denied/);
  const humanGateway=createSecurePilotGateway({gate:f.gate,backendUrl,
   allowInsecureBackend:true,backendSecretProvider:approle.provider,
   journal,receiptPrivatePem:receiptKey.privatePem,backendPublicPem:backendKey.publicPem,
   oauthResource:humanResource,delegationVerifier:delegated});
  await new Promise(resolve=>humanGateway.listen(0,'127.0.0.1',resolve));
  try{
   const humUrl='http://127.0.0.1:'+humanGateway.address().port+'/mcp';
   const humanCall=async(jwt,headers,argumentsObj=ARGS)=>{
    const response=await fetch(humUrl,{method:'POST',headers:{'content-type':'application/json',
     'mcp-protocol-version':'2026-07-28','mcp-method':'tools/call','mcp-name':'pay_invoice',
     authorization:'Bearer '+jwt,...headers},
     body:JSON.stringify({jsonrpc:'2.0',id:7,method:'tools/call',params:{name:TOOL,
      arguments:argumentsObj,_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28'}}})});
    await response.body?.cancel();return response.status;
   };
   const nowHuman=Math.floor(Date.now()/1000);
   const intentHuman=createIntent({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,
    args:ARGS,agentPrivatePem:f.agent.privatePem,now:nowHuman});
   const capHuman=f.iss.issue(intentHuman);
   const proofHuman=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,
    args:ARGS,capability:capHuman,agentPrivatePem:f.agent.privatePem,now:nowHuman});
   const baseHeaders={'x-faraday-capability':capHuman,
    'x-faraday-proof':Buffer.from(JSON.stringify(proofHuman)).toString('base64url')};
   assert.equal(await humanCall(humanBearer,baseHeaders),403,'human JWT alone cannot authorize');
   const delegatedHeaders={...baseHeaders,
    'x-faraday-delegation':Buffer.from(JSON.stringify([rootGrant])).toString('base64url')};
   assert.equal(await humanCall(good,delegatedHeaders),401,'service JWT cannot substitute for user');
   assert.equal(await humanCall(humanBearer,delegatedHeaders,{...ARGS,amount_cents:ARGS.amount_cents+1}),403);
   assert.equal(await humanCall(humanBearer,delegatedHeaders),200);
   assert.equal(store.count(),3,'one permitted human-backed synthetic effect');
   assert.equal(await humanCall(humanBearer,delegatedHeaders),403,'spent capability must never replay');
   humanRevoked=true;
   const newHumanIntent=createIntent({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,
    args:ARGS,agentPrivatePem:f.agent.privatePem,now:nowHuman});
   const newHumanCap=f.iss.issue(newHumanIntent);
   const newHumanProof=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,
    args:ARGS,capability:newHumanCap,agentPrivatePem:f.agent.privatePem,now:nowHuman});
   const revokedHeaders={'x-faraday-capability':newHumanCap,
    'x-faraday-proof':Buffer.from(JSON.stringify(newHumanProof)).toString('base64url'),
    'x-faraday-delegation':Buffer.from(JSON.stringify([rootGrant])).toString('base64url')};
   assert.equal(await humanCall(humanBearer,revokedHeaders),403,'revoked human permission must fail');
   assert.equal(store.count(),3);
  }finally{humanGateway.closeAllConnections();
   await new Promise(resolve=>humanGateway.close(resolve));}
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
    'argument-tampering-denied','capability-replay-denied','direct-backend-without-credential-denied',
    'vault-scoped-approle-secret-in-gateway','deny-other-vault-path',
    'vault-token-revocation-before-effect','scoped-token-reissue-recovers','keycloak-real-test-user-token',
    'user-token-operator-signed-root','signed-hop-scope-attenuation',
    'user-delegation-mcp-effect','service-token-cannot-use-user-grant',
    'user-delegation-revocation-denies'],
  issuerType:'official-keycloak',clientCredentialsFrom:'runtime-generated-CI-fixture',
  limitations:['Keycloak development-mode only','test-only certificate and realm',
    'user test uses lab-only password grant, NOT production OIDC authorization code / PKCE or token exchange',
    'real MCP synthetic execution with issuer-signed machine identity and operator-mapped agent, not token exchange or user delegation',
    'no production gateway deployment or enterprise R2 acceptance']}));
}else{throw Error('usage: keycloak-oidc-smoke.mjs prepare|verify ROOT');}
