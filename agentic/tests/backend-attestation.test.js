import test from 'node:test';
import assert from 'node:assert/strict';
import {newIdentity,digest} from '../lib/authority.js';
import {signBackendAttestation,verifyBackendAttestation} from '../lib/backend-attestation.js';

test('backend evidence rejects forged signatures and substituted operations',()=>{
  const key=newIdentity(),other=newIdentity(),operationId='operation-123456789012345678901';
  const requestHash=digest({tool:'pay_invoice',amount_cents:9500});
  const attestation=signBackendAttestation({privatePem:key.privatePem,claims:{version:1,operationId,requestHash,status:'simulated',recordedAt:100}});
  assert.equal(verifyBackendAttestation({publicPem:key.publicPem,attestation,operationId,requestHash}).verified,true);
  assert.throws(()=>verifyBackendAttestation({publicPem:other.publicPem,attestation,operationId,requestHash}),/invalid-backend-signature/);
  assert.throws(()=>verifyBackendAttestation({publicPem:key.publicPem,attestation,operationId:operationId+'x',requestHash}),/mismatch/);
  assert.throws(()=>verifyBackendAttestation({publicPem:key.publicPem,attestation:{...attestation,claims:{...attestation.claims,recordedAt:200}},operationId,requestHash}),/invalid-backend-signature/);
});
