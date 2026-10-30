/** Offline R2/R3 evidence collector. A manifest cannot attest its own files.
 * Verifies local byte hashes and binds every scenario to a commit. Not a claim
 * that the underlying integration run or its provenance is authentic.
 */
import {createHash} from 'node:crypto';
import {openSync, readFileSync, fstatSync, lstatSync, closeSync, realpathSync, constants} from 'node:fs';
import {resolve, sep, dirname} from 'node:path';
import {evaluateR2Evidence} from './r2-evidence-gate.js';
import {evaluateR3Manifest} from './r3-runtime-gate.js';
const digest = b => createHash('sha256').update(b).digest('hex');
const sha40 = /^[a-f0-9]{40}$/;
const sha64 = /^[a-f0-9]{64}$/;
const isObj = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const maxEvidenceBytes = 1024 * 1024;
const maxManifestBytes = 128 * 1024;
const FORMAT = Object.freeze({r2:'faraday.r2.real-trust-boundary.v1',r3:'faraday.r3.reliable-runtime.v1'});
function fileBytes(file, root, max) {
  const abs=resolve(root,file), canonicalRoot=realpathSync(root);
  const dir=realpathSync(dirname(abs));
  if (!abs.startsWith(resolve(root)+sep) || !(dir===canonicalRoot||dir.startsWith(canonicalRoot+sep)))
    throw Error('evidence-path-escape');
  const before=lstatSync(abs);
  if(!before.isFile()||before.isSymbolicLink())throw Error('unsafe-evidence-file');
  const fd=openSync(abs,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
  try {
    const s=fstatSync(fd);
    if(!s.isFile()||s.size<1||s.size>max||s.nlink!==1||s.ino!==before.ino||s.dev!==before.dev)throw Error('unsafe-evidence-file');
    const bytes=readFileSync(fd);
    if(bytes.length!==s.size)throw Error('evidence-file-changed');
    return bytes;
  } finally { closeSync(fd); }
}
function validPath(path, profile){
  return typeof path==='string' && path.length<=220 && path.startsWith('artifacts/'+profile+'/') &&
    /^artifacts\/(r2|r3)\/[A-Za-z0-9_.\/-]+\.json$/.test(path) &&
    path.split('/').every(s=>s&&s!=='.'&&s!=='..');
}
export function verifyEvidenceBundle({root,manifestPath,profile,expectedCommit}={}){
  if(!['r2','r3'].includes(profile)||!sha40.test(expectedCommit)||typeof root!=='string'||typeof manifestPath!=='string')
    throw Error('invalid-evidence-collector-arguments');
  const manifestBytes=fileBytes(manifestPath,root,maxManifestBytes);
  const report=JSON.parse(manifestBytes.toString('utf8'));
  if(!isObj(report)||report.format!==FORMAT[profile]||report.commit!==expectedCommit||!Array.isArray(report.checks))
    throw Error('invalid-evidence-manifest');
  if(report.checks.length===0||report.checks.length>100)throw Error('invalid-evidence-count');
  const seen=new Set();
  for(const check of report.checks){
    if(!isObj(check)||!validPath(check.artifact,profile)||seen.has(check.artifact)||!sha64.test(check.evidenceSha256??check.artifactSha256??''))
      throw Error('invalid-evidence-reference');
    seen.add(check.artifact);
  }
  for(const check of report.checks){
    const bytes=fileBytes(check.artifact,root,maxEvidenceBytes);
    const declared=profile==='r2'?check.evidenceSha256:check.artifactSha256;
    if(digest(bytes)!==declared)throw Error('evidence-digest-mismatch:'+check.id);
    const body=JSON.parse(bytes.toString('utf8'));
    if(!isObj(body)||body.id!==check.id||body.commit!==expectedCommit||body.result!==check.result||body.execution!==check.execution)
      throw Error('evidence-identity-mismatch:'+check.id);
  }
  // Ignore untrusted booleans; the collector has actually checked each file.
  const input=profile==='r2'?{...report,artifactDigestsVerified:true}:{...report,evidenceIndependentlyVerified:true};
  const result=profile==='r2'?evaluateR2Evidence(input,{expectedCommit}):evaluateR3Manifest(input,{expectedCommit});
  return {integrityPassed:true,manifestComplete:result.passed,releaseGatePassed:false,blockers:result.blockers,profile,commit:expectedCommit,filesChecked:seen.size,
    integrityVerified:true,executionProvenanceVerified:false,enterpriseCertified:false};
}
