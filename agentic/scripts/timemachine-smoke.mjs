import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {readSyntheticTrace} from '../lib/timemachine.js';
const workspace=mkdtempSync(join(tmpdir(),'faraday-timemachine-smoke-'));
const bin=resolve(dirname(fileURLToPath(import.meta.url)),'../bin/faraday.js');
try{
  const trace=join(workspace,'synthetic-trace.json');
  execFileSync(process.execPath,[bin,'timemachine','capture','--seed','42','--out',trace],{stdio:'pipe'});
  const x=readSyntheticTrace(trace);
  const r=JSON.parse(execFileSync(process.execPath,[bin,'timemachine','replay','--trace',trace,'--fail-on-divergence'],{encoding:'utf8'}));
  if(r.summary.divergences!==0||r.summary.steps!==x.steps.length)throw Error('TimeMachine smoke check failed');
  console.log(JSON.stringify({ok:true,steps:x.steps.length,divergences:r.summary.divergences,mode:'offline-no-effects'}));
}finally{rmSync(workspace,{recursive:true,force:true});}
