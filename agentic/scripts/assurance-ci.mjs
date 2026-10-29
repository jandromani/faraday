/** CI-controlled assurance evidence; no independent validation self-attestation. */
import {spawnSync} from 'node:child_process';
import {writeFileSync,mkdirSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {evaluateAssurance,ASSURANCE_FORMAT} from '../lib/assurance-gates.js';
const git=spawnSync('git',['rev-parse','HEAD'],{encoding:'utf8'});
const commit=process.env.GITHUB_SHA||git.stdout.trim();
if(!/^[a-f0-9]{40}$/.test(commit))throw Error('CI must have a real Git SHA');
const scenarios=[
 {id:'node-tests',kind:'unit',source:'ci/npm-test',args:['test']},
 {id:'oauth-http',kind:'integration',source:'ci/oauth-test',args:['run','oauth:test']},
 {id:'no-bypass-docker',kind:'adversarial_deployment',source:'ci/docker',args:['run','pilot:docker']}
];
const checks=[];
for(const s of scenarios){
 const r=spawnSync('npm',s.args,{cwd:resolve(import.meta.dirname,'..'),stdio:'inherit',timeout:120000});
 const result=r.status===0&&!r.error?'pass':'fail';
 checks.push({id:s.id,kind:s.kind,result,commit,source:s.source});
 if(result==='fail')break;
}
const report={format:ASSURANCE_FORMAT,commit,checks};
const result=evaluateAssurance(report,{profile:'developer',expectedCommit:commit});
const out=resolve(process.argv[2]||'artifacts/faraday-assurance.json');
mkdirSync(dirname(out),{recursive:true});
writeFileSync(out,JSON.stringify({...report,summary:result},null,2)+'\n');
console.log(JSON.stringify({output:out,passed:result.passed,blockers:result.blockers,enterpriseReady:false}));
if(!result.passed)process.exitCode=1;
