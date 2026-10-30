import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {PinnedOAuthResource} from '../lib/mcp-oauth-resource.js';
const issuer='https://127.0.0.1:18443/realms/faraday-r5',resource='https://gateway.example.test/mcp';
const now=1_800_000_000;
const pair=generateKeyPairSync('rsa',{modulusLength:2048});
const jwk={...pair.publicKey.export({format:'jwk'}),kid:'kc-test',alg:'RS256',use:'sig'};
const encode=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
const token=(claims={})=>{
 const header=encode({alg:'RS256',typ:'JWT',kid:'kc-test'});
 const payload=encode({iss:issuer,aud:['account',resource],sub:'service-account-uuid',azp:'faraday-r5',iat:now-5,exp:now+300,
  scope:'mcp:tools:read mcp:tools:execute',jti:'keycloak-test-jti-1234',...claims});
 return header+'.'+payload+'.'+sign('RSA-SHA256',Buffer.from(header+'.'+payload),pair.privateKey).toString('base64url');
};
const options={issuer,resource,publicJwks:[jwk],clock:()=>now};
test('default RFC9068 profile still denies OIDC JWT typ and azp-only tokens',()=>{
 const v=new PinnedOAuthResource(options);
 assert.throws(()=>v.verifyAuthorization('Bearer '+token(),'mcp:tools:read'),/invalid_token/);
});
test('explicit Keycloak profile validates pinned client, mixed audience and exact scopes',()=>{
 const v=new PinnedOAuthResource({...options,tokenProfile:'keycloak-oidc',allowedClientIds:['faraday-r5']});
 assert.equal(v.verifyAuthorization('Bearer '+token(),'mcp:tools:execute').clientId,'faraday-r5');
 assert.equal(v.verifyAuthorization('Bearer '+token(),'mcp:tools:read').subject,'service-account-uuid');
 for(const claims of [{azp:'rogue-r5'},{aud:['account']},{aud:resource+'-evil'},{iss:'https://attacker.example'},
  {sub:''},{scope:'mcp:tools:read'},{exp:now-10}]){
  assert.throws(()=>v.verifyAuthorization('Bearer '+token(claims),'mcp:tools:execute'));
 }
});
test('Keycloak profile refuses invalid configuration and tampered signatures',()=>{
 for(const allowedClientIds of [[],[''],['../faked'],new Array(17).fill('faraday-r5')])
  assert.throws(()=>new PinnedOAuthResource({...options,tokenProfile:'keycloak-oidc',allowedClientIds}));
 const v=new PinnedOAuthResource({...options,tokenProfile:'keycloak-oidc',allowedClientIds:['faraday-r5']});
 const a=token().split('.');a[1]=a[1].slice(0,-1)+(a[1].at(-1)==='A'?'B':'A');
 assert.throws(()=>v.verifyAuthorization('Bearer '+a.join('.'),'mcp:tools:read'),/invalid_token/);
});
test('locally revoked Keycloak subject denies valid signed token (failure denies)',()=>{
 const revocations={isRevoked:({subject})=>subject==='service-account-uuid'};
 const v=new PinnedOAuthResource({...options,tokenProfile:'keycloak-oidc',allowedClientIds:['faraday-r5'],revocations});
 assert.throws(()=>v.verifyAuthorization('Bearer '+token(),'mcp:tools:read'),/invalid_token/);
});
