#!/usr/bin/env node
/** Evidence-based acceptance reporter. Never labels enterprise epics as done. */
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve,dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
const project=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const manifest=JSON.parse(readFileSync(join(project,'docs/EPIC_CLOSURE_SCOPE_V1.json'),'utf8'));
const result=spawnSync(process.execPath,['--test','--test-reporter=tap','tests/closure-acceptance.test.js'],{
 cwd:project,encoding:'utf8',timeout:120000,maxBuffer:3*1024*1024,
 env:{...process.env,NODE_NO_WARNINGS:'1'},
});
const reportText=(result.stdout||'')+'\n'+(result.stderr||'');
const status=new Map();
for(const line of reportText.split(/\r?\n/)){
 const match=line.match(/^(ok|not ok)\s+\d+\s+-\s+\[(E\d\d)\]/);
 if(!match)continue;
 if(status.has(match[2]))throw Error('Duplicate acceptance gate '+match[2]);
 status.set(match[2],match[1]==='ok');
}
const checks=manifest.candidates.map(c=>({id:c.id,scope:c.scope,track:c.track,acceptancePass:status.get(c.id)===true,
 status:status.get(c.id)===true?'scoped-acceptance-passed':'blocked',enterpriseClosed:false,
 remaining:c.exclusions}));
const verified=result.status===0 && checks.every(x=>x.acceptancePass)&&status.size===checks.length;
const packageJson=JSON.parse(readFileSync(join(project,'package.json'),'utf8'));
const report={format:'faraday-epic-closure-report',version:1,packageVersion:packageJson.version,
 commit:process.env.GITHUB_SHA||null,platform:process.platform,arch:process.arch,node:process.version,
 securityCertification:false,enterpriseClosed:0,scopedAcceptancePasses:checks.filter(c=>c.acceptancePass).length,
 candidates:checks.length,passed:verified,
 gatedDeliverables:checks,
 note:'Passing acceptance checks does not imply all 32 original enterprise epics are closed. External compatibility, security audits and production validation remain.',
 evidenceSha256:createHash('sha256').update(JSON.stringify({version:packageJson.version,candidates:checks,threats:manifest.threats})).digest('hex')};
const outArg=process.argv.indexOf('--out');
if(outArg>=0){if(!process.argv[outArg+1])throw Error('--out requires a path');writeFileSync(resolve(process.argv[outArg+1]),JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});}
console.log(JSON.stringify({ok:report.passed,version:report.packageVersion,platform:report.platform,verified:report.scopedAcceptancePasses,total:report.candidates,
 enterpriseClosed:0,evidenceSha256:report.evidenceSha256,output:outArg>=0?resolve(process.argv[outArg+1]):null}));
if(!verified){console.error('Acceptance gate failed. Detailed TAP output follows:\n'+reportText.slice(-8000));process.exitCode=2;}
