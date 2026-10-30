import test from 'node:test';
import assert from 'node:assert/strict';
import {newIdentity} from '../lib/authority.js';
import {delegateNarrower} from '../lib/delegation-chain.js';
import {createVerifiedOidcDelegation,oidcPrincipalKey} from '../lib/oidc-delegation-binding.js';
const now=1800000000;
const issuer='https://login.example.test/realms/operators',subject='human-operator-uuid-1234';
const rootKey=newIdentity(),a=newIdentity(),b=newIdentity();
const agentA='faraday://r19/agent-a',agentB='faraday://r19/agent-b';
const exact={tool:'pay_invoice',resource:'invoice:demo',action:'pay',maxAmountCents:5000};
const oauthResource={issuer,verifyAuthorization:(authorization,scope)=>{
 if(!authorization?.startsWith('Bearer ')||scope!=='faraday:delegate')throw Error('unauthorized');
 if(authorization==='Bearer blocked')throw Error('revoked-jwt');
 return {subject:authorization==='Bearer other'?'other-human':subject,
  clientId:authorization==='Bearer machine'?'faraday-machine':'human-client',
  expiresAt:now+200,issuedAt:now-5,scope};
}};
const make=(opts={})=>createVerifiedOidcDelegation({
 oauthResource,issuerPrivatePem:rootKey.privatePem,issuerPublicPem:rootKey.publicPem,
 allowedUserClients:['human-client'],authorizeSubject:({subject:s})=>s===subject,
 agentPublicKeys:{[agentA]:a.publicPem,[agentB]:b.publicPem},clock:()=>now,
 revoked:()=>false,...opts
});
const expected=(agent,amount)=>({agent,tool:'pay_invoice',resource:'invoice:demo',action:'pay',amountCents:amount});
test('verified issuer+subject binds root and signed non-amplifying delegated hop',()=>{
 const v=make();
 const root=v.issue({authorizationHeader:'Bearer human',agent:agentA,scope:exact});
 const hop=delegateNarrower({fromPrivatePem:a.privatePem,fromAgent:agentA,
  toAgent:agentB,parent:root,maxAmountCents:2500,now,ttl:50});
 const verified=v.verify({authorizationHeader:'Bearer human',chain:[root,hop],expected:expected(agentB,2400)});
 assert.equal(verified.agent,agentB);
 assert.equal(verified.subject,oidcPrincipalKey({issuer,subject}));
 assert.equal(verified.maxAmountCents,2500);
 assert.throws(()=>v.verify({authorizationHeader:'Bearer human',chain:[root,hop],
  expected:expected(agentB,3000)}),/delegation-denied/);
});
test('token replacement, wrong client, missed human allowlist and async check fail closed',()=>{
 const v=make(),root=v.issue({authorizationHeader:'Bearer human',agent:agentA,scope:exact});
 for(const authorizationHeader of ['Bearer machine','Bearer other','Bearer blocked']){
  assert.throws(()=>v.verify({authorizationHeader,chain:[root],expected:expected(agentA,5000)}),/oidc-delegation-denied/);
  assert.throws(()=>v.issue({authorizationHeader,agent:agentA,scope:exact}),/oidc-delegation-denied/);
 }
 const asyncPolicy=make({authorizeSubject:()=>Promise.resolve(true)});
 assert.throws(()=>asyncPolicy.issue({authorizationHeader:'Bearer human',agent:agentA,scope:exact}),/oidc-delegation-denied/);
});
test('scope mutation, incomplete grant, grant expiry and revocation deny',()=>{
 const v=make(),root=v.issue({authorizationHeader:'Bearer human',agent:agentA,scope:exact});
 assert.throws(()=>v.verify({authorizationHeader:'Bearer human',chain:[root],
  expected:{...expected(agentA,5000),tool:'delete_all'}}),/delegation-denied/);
 assert.throws(()=>v.issue({authorizationHeader:'Bearer human',agent:agentA,
  scope:{...exact,maxAmountCents:90000}}),/oidc-delegation-denied|delegation-denied/);
 const revoked=make({revoked:(kind)=>kind==='subject'});
 assert.throws(()=>revoked.verify({authorizationHeader:'Bearer human',chain:[root],
  expected:expected(agentA,5000)}),/delegation-denied/);
 const expired=make({clock:()=>now+220});
 assert.throws(()=>expired.issue({authorizationHeader:'Bearer human',agent:agentA,scope:exact}),/oidc-delegation-denied/);
});
