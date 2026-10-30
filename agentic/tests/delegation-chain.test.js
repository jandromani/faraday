import test from 'node:test';
import assert from 'node:assert/strict';
import {newIdentity} from '../lib/authority.js';
import {issueDelegationRoot,delegateNarrower,verifyDelegationChain} from '../lib/delegation-chain.js';
const now=1800000000;
const human=newIdentity(),a=newIdentity(),b=newIdentity(),c=newIdentity();
const A='faraday://r14/agent-a',B='faraday://r14/agent-b',C='faraday://r14/agent-c';
const scope={tool:'pay_invoice',resource:'invoice:demo',action:'pay',maxAmountCents:10000};
const base=()=>issueDelegationRoot({issuerPrivatePem:human.privatePem,subject:'oidc:test-subject',agent:A,scope,now,ttl:300});
const narrower=(parent,from= A,to=B,key=a.privatePem,amount=5000)=>
 delegateNarrower({parent,fromAgent:from,toAgent:to,fromPrivatePem:key,
  maxAmountCents:amount,now,ttl:100});
const verify=(chain,overrides={})=>verifyDelegationChain({chain,
 issuerPublicPem:human.publicPem,agentPublicKeys:{[A]:a.publicPem,[B]:b.publicPem,[C]:c.publicPem},
 revoked:()=>false,expected:{agent:chain.at(-1).payload.kind==='root'?A:chain.at(-1).payload.to,
 tool:'pay_invoice',resource:'invoice:demo',action:'pay',amountCents:2500},
 now,...overrides});
test('operator-signed root and 2 Ed25519 agent hops attenuate rights',()=>{
 const r=base(),h1=narrower(r),h2=narrower(h1,B,C,b.privatePem,2500);
 const v=verify([r,h1,h2]);
 assert.equal(v.agent,C);assert.equal(v.maxAmountCents,2500);
 assert.equal(v.subject,'oidc:test-subject');
 assert.match(v.chainHash,/^[A-Za-z0-9_-]{43}$/);
 assert.throws(()=>verify([r,h1,h2],{expected:{agent:C,tool:'pay_invoice',resource:'invoice:demo',action:'pay',amountCents:2501}}),/delegation-denied/);
});
test('revocation of subject or any hop nonce fails closed',()=>{
 const root=base(),hop=narrower(root);
 for(const x of [root.payload.nonce,hop.payload.nonce,'oidc:test-subject']){
  assert.throws(()=>verify([root,hop],{revoked:(kind,id)=>id===x}),/delegation-denied/);
 }
 assert.throws(()=>verify([root,hop],{revoked:undefined}),/delegation-denied/);
});
test('agent cannot widen amount, extend parent expiry or change the signed scope',()=>{
 const root=base();
 assert.throws(()=>narrower(root,A,B,a.privatePem,15000),/delegation-denied/);
 assert.throws(()=>delegateNarrower({parent:root,fromAgent:A,toAgent:B,
  fromPrivatePem:a.privatePem,maxAmountCents:100,now,ttl:350}),/delegation-denied/);
 assert.throws(()=>verify([root],{expected:{agent:A,tool:'delete_all',resource:'invoice:demo',action:'pay',amountCents:1}}),/delegation-denied/);
});
test('cannot forge signatures, splice parent chains or reuse intermediate keys',()=>{
 const r=base(),h=narrower(r),tampered={...h,payload:{...h.payload,to:C}};
 assert.throws(()=>verify([r,tampered]),/delegation-denied/);
 const r2=base();
 assert.throws(()=>verify([r2,h]),/delegation-denied/);
 const fake=narrower(r,A,B,c.privatePem);
 assert.throws(()=>verify([r,fake]),/delegation-denied/);
 const revisited=narrower(h,B,A,b.privatePem,2000);
 assert.throws(()=>verify([r,h,revisited]),/delegation-denied/);
});
test('expired root, expired hop and missing registry fail closed',()=>{
 const root=base(),hop=narrower(root);
 assert.throws(()=>verify([root,hop],{now:now+400}),/delegation-denied/);
 assert.throws(()=>verify([root,hop],{agentPublicKeys:{[A]:c.publicPem}}),/delegation-denied/);
 assert.throws(()=>verify([root,hop],{revoked:()=>Promise.resolve(false)}),/delegation-denied/);
});
