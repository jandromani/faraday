/** Release evidence gates: passing unit tests never override failed deployment security. */
import {createHash,createPublicKey,verify} from 'node:crypto';
export const ASSURANCE_FORMAT='faraday-assurance/v1';
export const EVIDENCE_KINDS=Object.freeze(['unit','integration','adversarial_deployment','independent_validation']);
export const ENTERPRISE_REFERENCE_CONTROLS=Object.freeze(['idp-sso','workload-identity','tenant-isolation','secrets-lifecycle','tls',
 'observability','backup-recovery','ha-sla','deployment-isolation','adversarial-testing','independent-review','data-governance']);
const sha=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
function assert(ok,msg){if(!ok)throw Error(msg);}
const object=x=>x&&typeof x==='object'&&!Array.isArray(x);
const commitOk=x=>typeof x==='string'&&/^[a-f0-9]{40}$/.test(x);
const canonicalB64=x=>typeof x==='string'&&/^[A-Za-z0-9_-]+$/.test(x)&&Buffer.from(x,'base64url').toString('base64url')===x;
export function signableAttestationDigest({issuer,commit,evidenceDigest}){
 assert(typeof issuer==='string'&&/^[A-Za-z0-9_.:-]{3,100}$/.test(issuer),'invalid issuer');
 assert(commitOk(commit),'invalid commit');
 assert(typeof evidenceDigest==='string'&&/^[a-f0-9]{64}$/.test(evidenceDigest),'invalid evidenceDigest');
 return Buffer.from(['FARADAY-INDEPENDENT-V1',issuer,commit,evidenceDigest,''].join('\n'));
}
export function evaluateEnterpriseReference({commit,checks=[]}={}){
 assert(commitOk(commit),'invalid commit');
 assert(Array.isArray(checks)&&checks.length<=ENTERPRISE_REFERENCE_CONTROLS.length,'invalid reference checks');
 const byId=new Map();
 for(const check of checks){
  assert(object(check)&&Object.keys(check).every(key=>['id','result','evidenceSha256'].includes(key))&&
   ENTERPRISE_REFERENCE_CONTROLS.includes(check.id)&&['pass','fail','gap'].includes(check.result),'invalid reference check');
  assert(!byId.has(check.id),'duplicate reference check');
  if(check.result==='pass')assert(typeof check.evidenceSha256==='string'&&/^[a-f0-9]{64}$/.test(check.evidenceSha256),'missing evidence digest');
  else assert(check.evidenceSha256===undefined,'unexpected evidence digest');
  byId.set(check.id,{id:check.id,result:check.result,...(check.result==='pass'?{evidenceSha256:check.evidenceSha256}:{})});
 }
 const results=ENTERPRISE_REFERENCE_CONTROLS.map(id=>byId.get(id)??{id,result:'gap'});
 return {format:'faraday-enterprise-reference/v1',commit,checks:results,
  blockers:[...results.filter(check=>check.result!=='pass').map(check=>check.id+':'+check.result),'control-evidence-not-verified'],enterpriseReady:false,
  limitation:'Caller declarations and digests are not evidence verification, deployment attestation, auditor independence or enterprise readiness.'};
}
export function evaluateAssurance(report,{profile='developer',expectedCommit,trustRoots={}}={}){
 assert(['developer','enterprise'].includes(profile),'unknown assurance profile');
 assert(object(report)&&report.format===ASSURANCE_FORMAT,'invalid assurance format');
 assert(commitOk(report.commit),'invalid report commit');
 if(expectedCommit)assert(report.commit===expectedCommit,'commit mismatch');
 assert(Array.isArray(report.checks)&&report.checks.length>0&&report.checks.length<=200,'invalid checks');
 assert(object(trustRoots),'invalid trust roots');
 const seen=new Set(),kinds={},failures=[];
 for(const c of report.checks){
  assert(object(c)&&typeof c.id==='string'&&/^[A-Za-z0-9._-]{1,90}$/.test(c.id),'invalid check');
  assert(!seen.has(c.id),'duplicate check');seen.add(c.id);
  assert(EVIDENCE_KINDS.includes(c.kind),'unknown kind');
  assert(['pass','fail','gap'].includes(c.result),'invalid check result');
  assert(c.commit===report.commit,'mixed commit evidence');
  assert(typeof c.source==='string'&&/^[A-Za-z0-9._/-]{3,100}$/.test(c.source),'invalid source');
  if(c.kind==='independent_validation')assert(c.result!=='pass','independent validation must be externally attested');
  if(c.result!=='pass')failures.push(c.id+':'+c.result);
  kinds[c.kind]??={passed:0,failed:0,gaps:0};
  kinds[c.kind][c.result==='pass'?'passed':c.result==='fail'?'failed':'gaps']++;
 }
 for(const kind of EVIDENCE_KINDS.slice(0,3))if(!kinds[kind]?.passed)failures.push('missing:'+kind);
 const evidenceDigest=sha({format:report.format,commit:report.commit,checks:report.checks});
 let independentVerified=false;
 if(report.independentAttestation!==undefined){
  const a=report.independentAttestation;
  assert(object(a)&&typeof a.issuer==='string'&&typeof a.signature==='string','invalid attestation');
  assert(typeof a.evidenceDigest==='string'&&a.evidenceDigest===evidenceDigest,'attested evidence digest mismatch');
    const pem=Object.hasOwn(trustRoots,a.issuer)?trustRoots[a.issuer]:undefined;
  if(typeof pem==='string'&&canonicalB64(a.signature)){
      try{const key=createPublicKey(pem);independentVerified=key.asymmetricKeyType==='ed25519'&&verify(null,signableAttestationDigest({issuer:a.issuer,commit:report.commit,evidenceDigest}),key,Buffer.from(a.signature,'base64url'));}catch{independentVerified=false;}
  }
  if(!independentVerified)failures.push('independent-attestation-invalid');
 }
 if(profile==='enterprise'&&!independentVerified)failures.push('independent-validation-required');
 return Object.freeze({format:ASSURANCE_FORMAT,profile,commit:report.commit,evidenceDigest,independentVerified,checks:report.checks.length,breakdown:kinds,passed:failures.length===0,blockers:[...new Set(failures)],
  enterpriseEvidencePassed:profile==='enterprise'&&failures.length===0,enterpriseReady:false,
  limitation:'Signature verification against caller-supplied roots does not establish auditor independence or enterprise readiness.'});
}
