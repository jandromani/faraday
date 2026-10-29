import test from 'node:test';
import assert from 'node:assert/strict';
import {newIdentity,digest} from '../lib/authority.js';
import {signReceipt} from '../lib/pilot-receipts.js';
import {signBackendAttestation} from '../lib/backend-attestation.js';
import {createEvidenceCheckpoint,witnessEvidenceCheckpoint,verifyEvidenceCheckpoint,verifyWitnessedEvidence} from '../lib/evidence-checkpoint.js';

function fixture(){
  const gateway=newIdentity(),backend=newIdentity(),witness=newIdentity(),requestHash=digest('synthetic request');
  const receipt=operationId=>{
    const attestation=signBackendAttestation({privatePem:backend.privatePem,claims:{version:1,operationId,requestHash,status:'simulated',recordedAt:1000}});
    return signReceipt({privatePem:gateway.privatePem,claims:{version:1,operationId,agent:'agent',tool:'tool',resource:'resource',action:'action',argsHash:digest('args'),requestHash,rule:'rule',outcome:'simulated',responseHash:digest(attestation),backendAttestation:attestation,observedAt:1}});
  };
  const receipts=[receipt('operation-1234567890123456'),receipt('operation-2234567890123456')];
  const signing={gatewayPublicPem:gateway.publicPem,backendPublicPem:backend.publicPem,witnessPrivatePem:witness.privatePem,witnessId:'witness-one'};
  const verifying={gatewayPublicPem:gateway.publicPem,backendPublicPem:backend.publicPem,witnessPublicPem:witness.publicPem,expectedWitnessId:'witness-one'};
  return {gateway,backend,witness,receipts,signing,verifying};
}
test('checkpoint verifies all receipts and a separate witness signature',()=>{
  const x=fixture(),checkpoint=witnessEvidenceCheckpoint({...x.signing,receipts:x.receipts,issuedAt:1000});
  assert.equal(verifyEvidenceCheckpoint({...x.verifying,checkpoint}).count,2);
  assert.throws(()=>verifyEvidenceCheckpoint({...x.verifying,checkpoint:{...checkpoint,receipts:[...checkpoint.receipts].reverse()}}),/chain-mismatch/);
  assert.throws(()=>verifyEvidenceCheckpoint({...x.verifying,checkpoint:{...checkpoint,claims:{...checkpoint.claims,count:1}}}),/invalid-signature/);
  assert.throws(()=>witnessEvidenceCheckpoint({...x.signing,receipts:[x.receipts[0],x.receipts[0]]}),/duplicate/);
  assert.throws(()=>witnessEvidenceCheckpoint({...x.signing,witnessPrivatePem:x.gateway.privatePem,receipts:x.receipts}),/witness-key-not-independent/);
  assert.throws(()=>witnessEvidenceCheckpoint({...x.signing,backendPublicPem:newIdentity().publicPem,receipts:x.receipts}),/invalid-receipt/);
  assert.throws(()=>verifyEvidenceCheckpoint({...x.verifying,witnessPublicPem:newIdentity().publicPem,checkpoint}),/invalid-signature/);
});
test('trusted prefix detects rollback and supports separately trusted witness rotation',()=>{
  const x=fixture(),first=witnessEvidenceCheckpoint({...x.signing,receipts:x.receipts.slice(0,1)});
  const anchor=verifyEvidenceCheckpoint({...x.verifying,checkpoint:first}),trustedPrefix={count:anchor.count,root:anchor.root};
  const rotated=newIdentity(),second=witnessEvidenceCheckpoint({...x.signing,witnessPrivatePem:rotated.privatePem,witnessId:'witness-two',receipts:x.receipts});
  assert.equal(verifyEvidenceCheckpoint({...x.verifying,witnessPublicPem:rotated.publicPem,expectedWitnessId:'witness-two',checkpoint:second,trustedPrefix}).count,2);
  assert.throws(()=>verifyEvidenceCheckpoint({...x.verifying,checkpoint:first,trustedPrefix:{count:2,root:second.claims.root}}),/invalid-prefix/);
  assert.throws(()=>verifyEvidenceCheckpoint({...x.verifying,witnessPublicPem:rotated.publicPem,expectedWitnessId:'witness-two',checkpoint:second,trustedPrefix:{count:1,root:digest('other')}}),/prefix-mismatch/);
});
function legacyFixture(){
 const gateway=newIdentity(),backend=newIdentity(),witness=newIdentity(),attacker=newIdentity();
 const receipts=[];
 for(let i=0;i<3;i++){
   const operationId='operation-test-2026-000000'+i;
   const requestHash=digest({tool:'pay_invoice',resource:'invoice:demo',action:'pay',args:{amount_cents:4000+i,currency:'EUR',recipient:'supplier_demo'}});
   const attestation=signBackendAttestation({privatePem:backend.privatePem,claims:{version:1,operationId,requestHash,status:'simulated',recordedAt:100+i}});
   receipts.push(signReceipt({privatePem:gateway.privatePem,claims:{version:1,operationId,agent:'lab-agent',tool:'pay_invoice',resource:'invoice:demo',action:'pay',argsHash:digest({amount_cents:4000+i,currency:'EUR',recipient:'supplier_demo'}),requestHash,rule:'fixture',outcome:'simulated',responseHash:digest(attestation),backendAttestation:attestation,observedAt:100+i}}));
 }
 return {gateway,backend,witness,attacker,receipts};
}
const generate=x=>witnessEvidenceCheckpoint({checkpoint:createEvidenceCheckpoint({receipts:x.receipts,gatewayPublicPem:x.gateway.publicPem,backendPublicPem:x.backend.publicPem}),witnessPrivatePem:x.witness.privatePem,witnessId:'external-auditor-01',issuedAt:10000});
const verify=(x,attested,overrides={})=>verifyWitnessedEvidence({attested,gatewayPublicPem:x.gateway.publicPem,backendPublicPem:x.backend.publicPem,witnessPublicPem:x.witness.publicPem,expectedWitnessId:'external-auditor-01',...overrides});
test('three independent backend attestations, gateway receipts and witness signature validate offline',()=>{
 const x=legacyFixture(),envelope=generate(x);assert.deepEqual({verified:verify(x,envelope).verified,count:verify(x,envelope).count},{verified:true,count:3});
});
test('witness signature cannot be self-attested or substituted',()=>{
 const x=legacyFixture(),bundle=generate(x);
 assert.throws(()=>verify(x,bundle,{witnessPublicPem:x.attacker.publicPem}),/invalid-witness-signature/);
 assert.throws(()=>verify(x,bundle,{expectedWitnessId:'other-auditor'}),/invalid-checkpoint/);
 const checkpoint=createEvidenceCheckpoint({receipts:x.receipts,gatewayPublicPem:x.gateway.publicPem,backendPublicPem:x.backend.publicPem});
 const selfSigned=witnessEvidenceCheckpoint({checkpoint,witnessPrivatePem:x.gateway.privatePem,witnessId:'external-auditor-01',issuedAt:10000});
 assert.throws(()=>verify(x,selfSigned,{witnessPublicPem:x.gateway.publicPem}),/invalid-witness-signature/);
});
test('tampered, reordered or truncated records fail even with old witness signature',()=>{
 const x=legacyFixture(),bundle=generate(x);
 for(const subset of [bundle.checkpoint.receipts.slice(0,2),bundle.checkpoint.receipts.slice().reverse(),
   bundle.checkpoint.receipts.map((r,i)=>i? r:{...r,claims:{...r.claims,observedAt:999}})]){
   const altered=structuredClone(bundle);altered.checkpoint.receipts=subset;
   assert.throws(()=>verify(x,altered));
 }
});
test('duplicate receipt, forged backend and noncanonical receipt signatures are rejected',()=>{
 const x=legacyFixture();
 assert.throws(()=>createEvidenceCheckpoint({receipts:[x.receipts[0],x.receipts[0]],gatewayPublicPem:x.gateway.publicPem,backendPublicPem:x.backend.publicPem}),/duplicate/);
 assert.throws(()=>createEvidenceCheckpoint({receipts:[x.receipts[0]],gatewayPublicPem:x.gateway.publicPem,backendPublicPem:x.attacker.publicPem}),/invalid-receipt/);
 // JSON shape validation prevents signature substitution even if the backend record is unchanged.
 const wrong={...x.receipts[0],signature:x.receipts[0].signature+'A'};
 assert.throws(()=>createEvidenceCheckpoint({receipts:[wrong],gatewayPublicPem:x.gateway.publicPem,backendPublicPem:x.backend.publicPem}),/invalid-receipt/);
});

test('externally pinned root detects replay of a genuine but older signed checkpoint',()=>{
 const x=legacyFixture(),bundle=generate(x);
 assert.throws(()=>verify(x,bundle,{expectedRoot:'0'.repeat(64)}),/stale-checkpoint/);
 assert.throws(()=>verify(x,bundle,{minimumCount:4}),/stale-checkpoint/);
 assert.equal(verify(x,bundle,{expectedRoot:bundle.checkpoint.summary.root,minimumCount:3}).verified,true);
});
