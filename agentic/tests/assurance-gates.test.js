import {test} from 'node:test';import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {evaluateAssurance,signableAttestationDigest,ASSURANCE_FORMAT,evaluateEnterpriseReference,ENTERPRISE_REFERENCE_CONTROLS} from '../lib/assurance-gates.js';
const commit='b'.repeat(40);
const sample=(adversarial='pass')=>({format:ASSURANCE_FORMAT,commit,checks:[
 {id:'unit',kind:'unit',result:'pass',source:'ci/node',commit},
 {id:'integration',kind:'integration',result:'pass',source:'ci/http',commit},
 {id:'network',kind:'adversarial_deployment',result:adversarial,source:'ci/docker',commit},
]});
test('E31 reference controls default to gaps and declarations never prove enterprise readiness',()=>{
 const missing=evaluateEnterpriseReference({commit});assert.equal(missing.blockers.length,ENTERPRISE_REFERENCE_CONTROLS.length+1);assert.equal(missing.enterpriseReady,false);
 const checks=ENTERPRISE_REFERENCE_CONTROLS.map(id=>({id,result:'pass',evidenceSha256:'a'.repeat(64)}));
 const report=evaluateEnterpriseReference({commit,checks});assert.deepEqual(report.blockers,['control-evidence-not-verified']);assert.equal(report.enterpriseReady,false);
 assert.match(report.limitation,/not evidence verification/);
 assert.throws(()=>evaluateEnterpriseReference({commit,checks:[{id:'tls',result:'pass'}]}),/missing evidence/);
 assert.throws(()=>evaluateEnterpriseReference({commit,checks:[checks[0],checks[0]]}),/duplicate/);
 assert.throws(()=>evaluateEnterpriseReference({commit,checks:[{id:'fake',result:'pass'}]}),/invalid reference/);
});
test('Developer profile requires unit + integration + adversarial deployment',()=>{
 const r=evaluateAssurance(sample(),{expectedCommit:commit});assert.equal(r.passed,true);assert.equal(r.enterpriseReady,false);
});
test('Failed bypass blocks even with hundreds of successful unit suites',()=>{
 const x=sample('fail');
 for(let i=0;i<180;i++)x.checks.push({id:'u'+i,kind:'unit',result:'pass',source:'ci/node',commit});
 const r=evaluateAssurance(x);assert.equal(r.passed,false);assert.ok(r.blockers.includes('network:fail'));
});
test('Missing, GAP, duplicate and cross-commit evidence cannot pass',()=>{
 for(const state of ['fail','gap'])assert.equal(evaluateAssurance(sample(state)).passed,false);
 const missing=sample();missing.checks.pop();assert.equal(evaluateAssurance(missing).passed,false);
 const dup=sample();dup.checks.push(dup.checks[0]);assert.throws(()=>evaluateAssurance(dup),/duplicate/);
 assert.throws(()=>evaluateAssurance(sample(),{expectedCommit:'a'.repeat(40)}),/commit mismatch/);
});
test('Enterprise requires independent signature from pinned third-party trust root',()=>{
 const report=sample(),{privateKey,publicKey}=generateKeyPairSync('ed25519');
 const before=evaluateAssurance(report,{profile:'enterprise'});assert.equal(before.passed,false);
 const issuer='external-lab-01',evidenceDigest=before.evidenceDigest;
 const signature=sign(null,signableAttestationDigest({issuer,commit,evidenceDigest}),privateKey).toString('base64url');
 report.independentAttestation={issuer,evidenceDigest,signature};
 const trustRoots={[issuer]:publicKey.export({type:'spki',format:'pem'})};
 const verified=evaluateAssurance(report,{profile:'enterprise',trustRoots});
 assert.equal(verified.passed,true);assert.equal(verified.enterpriseEvidencePassed,true);assert.equal(verified.enterpriseReady,false);
 assert.match(verified.limitation,/does not establish auditor independence/);
 assert.equal(evaluateAssurance(report,{profile:'enterprise',trustRoots:Object.create(trustRoots)}).independentVerified,false);
 const other=generateKeyPairSync('ed448');
 const otherSignature=sign(null,signableAttestationDigest({issuer,commit,evidenceDigest}),other.privateKey).toString('base64url');
 const otherReport={...report,independentAttestation:{issuer,evidenceDigest,signature:otherSignature}};
 assert.equal(evaluateAssurance(otherReport,{profile:'enterprise',trustRoots:{[issuer]:other.publicKey.export({type:'spki',format:'pem'})}}).independentVerified,false);
 assert.equal(evaluateAssurance(report,{profile:'enterprise',trustRoots:{}}).enterpriseReady,false);
 report.checks[0].id='tampered';assert.throws(()=>evaluateAssurance(report,{profile:'enterprise',trustRoots}),/digest mismatch/);
});
