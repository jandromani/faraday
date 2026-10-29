import test from 'node:test';
import assert from 'node:assert/strict';
import {evaluateR2Evidence,R2_FORMAT,R2_SCENARIOS} from '../lib/r2-evidence-gate.js';
const commit='a'.repeat(40),digest='b'.repeat(64);
function fixture(){
 return {format:R2_FORMAT,commit,environment:'isolated-reference-deployment',
 vault:{provider:'hashicorp-vault-kv2',mode:'live'},
 idp:{mode:'live',issuer:'https://idp.example.test'},
 gateway:{transport:'mcp-stdio',backendIsolated:true},
 artifactDigestsVerified:true,
 checks:R2_SCENARIOS.map(id=>({id,result:'pass',execution:'live',evidenceSha256:digest,artifact:'artifacts/r2/'+id+'.json',commit}))};
}
test('accepts complete bound evidence manifest (not a proof that evidence exists)',()=>{
 assert.equal(evaluateR2Evidence(fixture(),{expectedCommit:commit}).passed,true);
});
for(const [name,mutation] of [
 ['missing negative control',x=>x.checks.pop()],
 ['simulated idp',x=>x.idp.mode='simulated'],
 ['simulated vault',x=>x.vault.mode='mock'],
 ['unisolated backend',x=>x.gateway.backendIsolated=false],
 ['unverified artifact digest',x=>x.artifactDigestsVerified=false],
 ['failed revocation',x=>x.checks[1].result='fail'],
 ['replayed check',x=>x.checks.push({...x.checks[0]})],
 ['missing file digest',x=>x.checks[0].evidenceSha256=''],
 ['wrong source commit',x=>x.checks[0].commit='c'.repeat(40)],
 ['path traversal',x=>x.checks[0].artifact='artifacts/r2/../../secrets'],
 ['synthetic adversary',x=>x.checks[6].execution='synthetic'],
 ['missing issuer',x=>x.idp.issuer='http://localhost'],
 ])test('R2 rejects '+name,()=>{const x=fixture();mutation(x);assert.equal(evaluateR2Evidence(x,{expectedCommit:commit}).passed,false);});
test('R2 rejects unknown and mismatching commits',()=>{
 assert.equal(evaluateR2Evidence(fixture(),{expectedCommit:'f'.repeat(40)}).passed,false);
 assert.equal(evaluateR2Evidence(null).passed,false);
});
