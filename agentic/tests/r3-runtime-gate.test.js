import test from 'node:test';
import assert from 'node:assert/strict';
import {R3_FORMAT,R3_SCENARIOS,evaluateR3Manifest} from '../lib/r3-runtime-gate.js';
const commit='a'.repeat(40);
function fixture(){return {format:R3_FORMAT,commit,environment:'isolated-integration',evidenceIndependentlyVerified:true,
 benchmark:{p95Ms:25,limitMs:50,samples:200},
 checks:R3_SCENARIOS.map(id=>({id,commit,execution:'integration',result:'pass',artifact:'artifacts/r3/'+id+'.json',artifactSha256:'b'.repeat(64)}))};}
test('R3 accepts structurally complete externally verified evidence',()=>assert.equal(evaluateR3Manifest(fixture(),{expectedCommit:commit}).passed,true));
for(const [name,change] of [
 ['missing HA failover',x=>x.checks.splice(5,1)],
 ['split brain failure',x=>x.checks[6].result='fail'],
 ['approval not tested',x=>x.checks.splice(9,1)],
 ['replayed test entry',x=>x.checks.push({...x.checks[0]})],
 ['non-integration test',x=>x.checks[0].execution='unit'],
 ['artifact traversal',x=>x.checks[0].artifact='artifacts/r3/../secret'],
 ['mismatching commit',x=>x.checks[0].commit='f'.repeat(40)],
 ['unverified artifact',x=>x.evidenceIndependentlyVerified=false],
 ['benchmark p95 outside SLO',x=>x.benchmark.p95Ms=51],
 ['benchmark too few samples',x=>x.benchmark.samples=99],
 ['non-finite benchmark',x=>x.benchmark.p95Ms=Infinity],
 ])test('R3 rejects '+name,()=>{const x=fixture();change(x);assert.equal(evaluateR3Manifest(x,{expectedCommit:commit}).passed,false);});
test('R3 rejects unexpected SHA and null',()=>{
 assert.equal(evaluateR3Manifest(fixture(),{expectedCommit:'0'.repeat(40)}).passed,false);
 assert.equal(evaluateR3Manifest(null).passed,false);
});
