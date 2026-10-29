import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync,symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {verifyEvidenceBundle} from '../lib/verified-evidence.js';
import {R2_SCENARIOS} from '../lib/r2-evidence-gate.js';
import {R3_SCENARIOS} from '../lib/r3-runtime-gate.js';
const COMMIT='a'.repeat(40);
const hash=v=>createHash('sha256').update(v).digest('hex');
function setup(t,profile){
 const root=mkdtempSync(join(tmpdir(),'faraday-evidence-'));t.after(()=>rmSync(root,{recursive:true,force:true}));
 mkdirSync(join(root,'artifacts',profile),{recursive:true});
 const ids=profile==='r2'?R2_SCENARIOS:R3_SCENARIOS;
 const checks=ids.map(id=>{
  const execution=profile==='r2'?'live':'integration';
  const json=JSON.stringify({id,commit:COMMIT,result:'pass',execution});
  const artifact=`artifacts/${profile}/${id}.json`;
  writeFileSync(join(root,artifact),json);
  return {id,commit:COMMIT,result:'pass',execution,artifact,...(profile==='r2'?{evidenceSha256:hash(json)}:{artifactSha256:hash(json)})};
 });
 const manifest={format:profile==='r2'?'faraday.r2.real-trust-boundary.v1':'faraday.r3.reliable-runtime.v1',commit:COMMIT,checks,
  ...(profile==='r2'?{environment:'isolated-reference-deployment',vault:{provider:'hashicorp-vault-kv2',mode:'live'},idp:{mode:'live',issuer:'https://example.test'},gateway:{transport:'mcp-stdio',backendIsolated:true},artifactDigestsVerified:false}:
   {environment:'isolated-integration',benchmark:{p95Ms:8,limitMs:20,samples:200},evidenceIndependentlyVerified:false})};
 const manifestPath=`manifest-${profile}.json`;const save=()=>writeFileSync(join(root,manifestPath),JSON.stringify(manifest));save();
 return {root,profile,manifest,manifestPath,save,run:()=>verifyEvidenceBundle({root,profile,manifestPath,expectedCommit:COMMIT})};
}
for(const profile of ['r2','r3']){
 test('collector verifies actual bytes; untrusted attestation flags ignored: '+profile,t=>{
  const f=setup(t,profile);const result=f.run();assert.equal(result.passed,true);
  assert.equal(result.filesChecked,profile==='r2'?10:17);assert.equal(result.executionProvenanceVerified,false);
 });
 test('collector rejects tampered evidence: '+profile,t=>{
  const f=setup(t,profile);writeFileSync(join(f.root,f.manifest.checks[0].artifact),'{}');
  assert.throws(f.run,/evidence-digest-mismatch/);
 });
 test('collector rejects fabricated digest: '+profile,t=>{
  const f=setup(t,profile);f.manifest.checks[0][profile==='r2'?'evidenceSha256':'artifactSha256']='b'.repeat(64);
  f.save();assert.throws(f.run,/evidence-digest-mismatch/);
 });
 test('collector rejects traversal, duplicate paths, wrong SHA commit: '+profile,t=>{
  const f=setup(t,profile);
  f.manifest.checks[0].artifact=`artifacts/${profile}/../secret.json`;f.save();assert.throws(f.run,/invalid-evidence-reference/);
  f.manifest.checks[0].artifact=f.manifest.checks[1].artifact;f.save();assert.throws(f.run,/invalid-evidence-reference/);
  f.manifest.commit='b'.repeat(40);f.save();assert.throws(f.run,/invalid-evidence-manifest/);
 });
 test('collector rejects symlink artifact: '+profile,t=>{
  const f=setup(t,profile),path=join(f.root,f.manifest.checks[0].artifact),alias=join(f.root,'artifacts',profile,'alias.json');
  try{symlinkSync(path,alias);}catch(e){if(process.platform==='win32'&&e.code==='EPERM'){t.skip('symlink permissions');return;}throw e;}
  f.manifest.checks[0].artifact=`artifacts/${profile}/alias.json`;f.save();assert.throws(f.run,/unsafe-evidence-file/);
 });
}
