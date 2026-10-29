import test from 'node:test';
import assert from 'node:assert/strict';
import {newIdentity,digest} from '../lib/authority.js';
import {signReceipt} from '../lib/pilot-receipts.js';
import {signBackendAttestation} from '../lib/backend-attestation.js';
import {witnessEvidenceCheckpoint,verifyEvidenceCheckpoint} from '../lib/evidence-checkpoint.js';

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