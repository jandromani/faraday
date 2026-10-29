/** R3 Reliable Runtime acceptance gate. This checks the shape of externally measured
 * evidence, not the authenticity of evidence or real HA by itself. */
export const R3_FORMAT='faraday.r3.reliable-runtime.v1';
export const R3_SCENARIOS=Object.freeze([
 'idempotent-retry-single-effect','idempotency-key-conflict-denied',
 'crash-before-commit-recovery','crash-after-commit-recovery',
 'signed-backup-restore-and-rollback-denial',
 'two-node-failover-no-double-effect','split-brain-no-double-writer',
 'agent-budget-atomicity','organization-budget-atomicity',
 'expired-approval-denied','duplicate-approver-key-denied',
 'sentinel-deny-quarantine-stop','sentinel-recovery-audited',
 'timemachine-replay-offline-only','fuzz-corpus-no-crashes',
 'chaos-injection-recovery','benchmark-p95-under-policy'
]);
const isObj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const sha40=x=>typeof x==='string'&&/^[a-f0-9]{40}$/.test(x);
const sha64=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
export function evaluateR3Manifest(report,{expectedCommit}={}){
 const blockers=[];const fail=s=>blockers.push(s);
 if(!isObj(report))return {passed:false,blockers:['invalid-report'],enterpriseReady:false};
 if(report.format!==R3_FORMAT)fail('format');
 if(!sha40(report.commit)||(expectedCommit!==undefined&&report.commit!==expectedCommit))fail('commit');
 if(report.environment!=='isolated-integration')fail('environment');
 if(report.evidenceIndependentlyVerified!==true)fail('evidence-not-independently-verified');
 const entries=Array.isArray(report.checks)?report.checks:[];
 const seen=new Set();
 for(const c of entries){
  if(!isObj(c)||!R3_SCENARIOS.includes(c.id)){fail('unknown-check');continue;}
  if(seen.has(c.id))fail('duplicate:'+c.id);seen.add(c.id);
  if(c.commit!==report.commit||c.result!=='pass'||!sha64(c.artifactSha256)||c.execution!=='integration')
   fail('invalid-check:'+c.id);
  if(typeof c.artifact!=='string'||!/^artifacts\/r3\/[A-Za-z0-9._/-]+$/.test(c.artifact)||c.artifact.includes('..'))
   fail('artifact:'+c.id);
 }
 for(const id of R3_SCENARIOS)if(!seen.has(id))fail('missing:'+id);
 if(!isObj(report.benchmark)||!Number.isFinite(report.benchmark.p95Ms)||report.benchmark.p95Ms<0||
    !Number.isFinite(report.benchmark.limitMs)||report.benchmark.limitMs<=0||
    report.benchmark.p95Ms>report.benchmark.limitMs||!Number.isSafeInteger(report.benchmark.samples)||report.benchmark.samples<100)
  fail('benchmark-slo');
 return {passed:blockers.length===0,blockers,enterpriseReady:false,scope:'developer-preview'};
}
