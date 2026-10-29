import test from 'node:test';
import assert from 'node:assert/strict';
import {newIdentity,digest} from '../lib/authority.js';
import {signBackendAttestation} from '../lib/backend-attestation.js';
import {signReceipt} from '../lib/pilot-receipts.js';
import {createEvidenceCheckpoint,witnessEvidenceCheckpoint,verifyWitnessedEvidence} from '../lib/evidence-checkpoint.js';
function fixture(){
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
 const x=fixture(),envelope=generate(x);assert.deepEqual({verified:verify(x,envelope).verified,count:verify(x,envelope).count},{verified:true,count:3});
});
test('witness signature cannot be self-attested or substituted',()=>{
 const x=fixture(),bundle=generate(x);
 assert.throws(()=>verify(x,bundle,{witnessPublicPem:x.attacker.publicPem}),/invalid-witness-signature/);
 assert.throws(()=>verify(x,bundle,{expectedWitnessId:'other-auditor'}),/invalid-checkpoint/);
});
test('tampered, reordered or truncated records fail even with old witness signature',()=>{
 const x=fixture(),bundle=generate(x);
 for(const subset of [bundle.checkpoint.receipts.slice(0,2),bundle.checkpoint.receipts.slice().reverse(),
   bundle.checkpoint.receipts.map((r,i)=>i? r:{...r,claims:{...r.claims,observedAt:999}})]){
   const altered=structuredClone(bundle);altered.checkpoint.receipts=subset;
   assert.throws(()=>verify(x,altered));
 }
});
test('duplicate receipt, forged backend and noncanonical receipt signatures are rejected',()=>{
 const x=fixture();
 assert.throws(()=>createEvidenceCheckpoint({receipts:[x.receipts[0],x.receipts[0]],gatewayPublicPem:x.gateway.publicPem,backendPublicPem:x.backend.publicPem}),/duplicate/);
 assert.throws(()=>createEvidenceCheckpoint({receipts:[x.receipts[0]],gatewayPublicPem:x.gateway.publicPem,backendPublicPem:x.attacker.publicPem}),/invalid-receipt/);
 // JSON shape validation prevents signature substitution even if the backend record is unchanged.
 const wrong={...x.receipts[0],signature:x.receipts[0].signature+'A'};
 assert.throws(()=>createEvidenceCheckpoint({receipts:[wrong],gatewayPublicPem:x.gateway.publicPem,backendPublicPem:x.backend.publicPem}),/invalid-receipt/);
});

test('externally pinned root detects replay of a genuine but older signed checkpoint',()=>{
 const x=fixture(),bundle=generate(x);
 assert.throws(()=>verify(x,bundle,{expectedRoot:'0'.repeat(64)}),/stale-checkpoint/);
 assert.throws(()=>verify(x,bundle,{minimumCount:4}),/stale-checkpoint/);
 assert.equal(verify(x,bundle,{expectedRoot:bundle.checkpoint.summary.root,minimumCount:3}).verified,true);
});
