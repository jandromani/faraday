/** R2 evidence gate: evidence is produced by external integration jobs, never inferred from unit tests.
 * No embedded tokens, synthetic-only results or self-declared enterprise certification.
 */
export const R2_FORMAT='faraday.r2.real-trust-boundary.v1';
export const R2_SCENARIOS=Object.freeze([
  'vault-live-kv2-read',
  'vault-live-revocation',
  'idp-live-token-accept',
  'idp-live-revocation',
  'mcp-authorized-operation-receipt',
  'mcp-denied-operation',
  'rogue-agent-backend-denied',
  'rogue-agent-secrets-denied',
  'gateway-backend-positive',
  'network-bypass-negative'
]);
const hex=/^[a-f0-9]{64}$/;
const sha=/^[a-f0-9]{40}$/;
export function evaluateR2Evidence(report,{expectedCommit}={}){
  const blockers=[];
  const fail=x=>blockers.push(x);
  if(!report||typeof report!=='object'||Array.isArray(report))return {passed:false,blockers:['invalid-report'],profile:'developer-preview'};
  if(report.format!==R2_FORMAT)fail('format');
  if(!sha.test(report.commit||'')|| (expectedCommit&&report.commit!==expectedCommit))fail('commit');
  if(report.environment!=='isolated-reference-deployment')fail('environment');
  if(report.vault?.provider!=='hashicorp-vault-kv2'||report.vault?.mode!=='live')fail('vault-live-required');
  if(report.idp?.mode!=='live'||typeof report.idp?.issuer!=='string'||!report.idp.issuer.startsWith('https://'))fail('idp-live-required');
  if(report.gateway?.transport!=='mcp-stdio'||report.gateway?.backendIsolated!==true)fail('mcp-gateway-required');
  const entries=Array.isArray(report.checks)?report.checks:[];
  const seen=new Set();
  for(const item of entries){
    if(!item||typeof item!=='object'||typeof item.id!=='string'||!R2_SCENARIOS.includes(item.id)){fail('unexpected-check');continue;}
    if(seen.has(item.id))fail('duplicate:'+item.id);
    seen.add(item.id);
    if(item.result!=='pass'||item.execution!=='live'||!hex.test(item.evidenceSha256||''))fail('invalid-evidence:'+item.id);
    if(typeof item.artifact!=='string'||!/^artifacts\/r2\/[A-Za-z0-9._/-]+$/.test(item.artifact)||item.artifact.includes('..'))fail('artifact:'+item.id);
    if(item.commit!==report.commit)fail('check-commit:'+item.id);
  }
  for(const id of R2_SCENARIOS)if(!seen.has(id))fail('missing:'+id);
  // Hash references must be independently checked against real files by the CI collector.
  if(report.artifactDigestsVerified!==true)fail('artifact-digests-unverified');
  return {passed:blockers.length===0,blockers,profile:'developer-preview',enterpriseCertified:false};
}
