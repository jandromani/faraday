#!/usr/bin/env node
/** R5 real HTTPS Keycloak issuer smoke. Tests issuer-signed bearer tokens.
 * Disposable CI-only realm; no production SSO onboarding claim.
 */
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {mkdirSync,writeFileSync,readFileSync} from 'node:fs';
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
 writeFileSync(join(importDir,'faraday-realm.json'),JSON.stringify(realm),{mode:0o644,flag:'wx'});
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
 console.log(JSON.stringify({kind:'faraday-r5-real-https-oidc',result:'pass',
  controls:['TLS-validated-OIDC-discovery','provider-issued-RS256-token','pinned-JWKS',
    'exact-resource-audience','read-scope','execute-scope','authorized-client-only',
    'forged-signature-denied','local-revocation-denied'],
  issuerType:'official-keycloak',clientCredentialsFrom:'runtime-generated-CI-fixture',
  limitations:['Keycloak development-mode only','test-only certificate and realm',
    'no production SSO, token exchange or agent delegation attestation',
    'not full real-gateway or R2 enterprise acceptance']}));
}else{throw Error('usage: keycloak-oidc-smoke.mjs prepare|verify ROOT');}
