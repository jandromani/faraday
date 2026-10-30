/** R19: verified OIDC principal -> Ed25519 operator grant -> attenuated agent chain.
 * DOES NOT implement OAuth token-exchange or real user-consent workflow.
 * Call the verifier at execution time; a stale token/root must fail closed.
 */
import {digest} from './authority.js';
import {issueDelegationRoot,verifyDelegationChain} from './delegation-chain.js';
const fail=()=>{throw Error('oidc-delegation-denied');};
const ids=x=>Array.isArray(x)&&x.length>=1&&x.length<=16&&
 x.every(z=>typeof z==='string'&&/^[A-Za-z0-9_.-]{3,128}$/.test(z));
const agent=x=>typeof x==='string'&&/^faraday:\/\/[A-Za-z0-9/_-]{3,160}$/.test(x);
const scopeOK=x=>x&&typeof x==='object'&&Object.keys(x).sort().join('|')===
 'action|maxAmountCents|resource|tool'&&
 ['action','resource','tool'].every(k=>typeof x[k]==='string'&&x[k].length>0)&&
 Number.isSafeInteger(x.maxAmountCents)&&x.maxAmountCents>=1&&x.maxAmountCents<=20000;
export const oidcPrincipalKey=({issuer,subject})=>{
 if(typeof issuer!=='string'||!issuer.startsWith('https://')||
  typeof subject!=='string'||subject.length<3||subject.length>256)fail();
 return 'oidc:'+Buffer.from(digest({issuer,subject}),'base64url').toString('hex');
};
export function createVerifiedOidcDelegation({
 oauthResource,issuerPrivatePem,issuerPublicPem,allowedUserClients,
 authorizeSubject,agentPublicKeys,revoked=()=>false,
 clock=()=>Math.floor(Date.now()/1000),maxRootTtlSec=120
}={}){
 if(!oauthResource||typeof oauthResource.verifyAuthorization!=='function'||
  typeof oauthResource.issuer!=='string'||!ids(allowedUserClients)||
  typeof issuerPrivatePem!=='string'||typeof issuerPublicPem!=='string'||
  typeof authorizeSubject!=='function'||!agentPublicKeys||
  typeof revoked!=='function'||typeof clock!=='function'||
  !Number.isSafeInteger(maxRootTtlSec)||maxRootTtlSec<1||maxRootTtlSec>300)fail();
 const clients=new Set(allowedUserClients);
 const identityFor=authorizationHeader=>{
  let identity;
  try{identity=oauthResource.verifyAuthorization(authorizationHeader,'faraday:delegate');}
  catch{fail();}
  if(!identity||!clients.has(identity.clientId)||
   !Number.isSafeInteger(identity.expiresAt)||!Number.isSafeInteger(identity.issuedAt)||
   identity.expiresAt<=clock()||identity.expiresAt-identity.issuedAt>3600)fail();
  // The trusted operator callback must identify a real enabled human subject.
  // This callback MUST NOT infer "human" solely from username or email claims.
  try{
   if(authorizeSubject({issuer:oauthResource.issuer,subject:identity.subject,clientId:identity.clientId})!==true)fail();
  }catch{fail();}
  return identity;
 };
 return Object.freeze({
  issue({authorizationHeader,agent:target,scope}={}){
   const identity=identityFor(authorizationHeader),now=clock();
   if(!agent(target)||!scopeOK(scope))fail();
   const ttl=Math.min(maxRootTtlSec,identity.expiresAt-now);
   if(ttl<1)fail();
   return issueDelegationRoot({issuerPrivatePem,subject:oidcPrincipalKey({issuer:oauthResource.issuer,subject:identity.subject}),
    agent:target,scope,now,ttl});
  },
  verify({authorizationHeader,chain,expected}={}){
   const identity=identityFor(authorizationHeader),now=clock();
   if(!Array.isArray(chain)||chain.length<1||chain.length>4||!expected||!agent(expected.agent))fail();
   const bound=oidcPrincipalKey({issuer:oauthResource.issuer,subject:identity.subject});
   const checked=verifyDelegationChain({chain,issuerPublicPem,agentPublicKeys,revoked,expected,now});
   if(checked.subject!==bound||checked.expiresAt>identity.expiresAt)fail();
   return Object.freeze(checked);
  }
 });
}
