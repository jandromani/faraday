import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {probeStdio} from '../lib/mcp-live-probe.js';
const fixture=fileURLToPath(new URL('./probe-fixture.cjs',import.meta.url));
const cli=fileURLToPath(new URL('../bin/faraday.js',import.meta.url));
function envConfig(era){
 const root=mkdtempSync(join(tmpdir(),'faraday-probe-'));
 const conf=join(root,'mcp.json');
 writeFileSync(conf,JSON.stringify({mcpServers:{sample:{command:process.execPath,args:[fixture,era]}}}));
 return {root,conf,clean:()=>rmSync(root,{recursive:true,force:true})};
}
for(const era of ['modern','legacy']){
 test(`active discovery: ${era} tools/list pagination, no side-effects`,async()=>{
  const c=envConfig(era);
  try{const r=await probeStdio({configFile:c.conf,server:'sample',timeoutMs:3000});
  assert.equal(r.era,era);assert.equal(r.pages,2);assert.equal(r.toolsObserved,2);
  assert.equal(r.invokedTools,false);assert.equal(r.result,'pass');
  assert.doesNotMatch(JSON.stringify(r),/SENSITIVE_SECRET/);
  }finally{c.clean()}
 });
}
test('read-only probe refuses arbitrary tool calls without explicit opt-in',async()=>{
 const c=envConfig('modern');try{await assert.rejects(()=>probeStdio({configFile:c.conf,server:'sample',callTool:'read_only_fixture'}),/allow-call/);}finally{c.clean()}
});
test('explicit synthetic call does not copy tool outputs to report',async()=>{
 const c=envConfig('modern');try{const r=await probeStdio({configFile:c.conf,server:'sample',callTool:'read_only_fixture',allowCall:true,timeoutMs:3000});
 assert.equal(r.toolCall.success,true);assert.doesNotMatch(JSON.stringify(r),/SENSITIVE_SECRET/);
 }finally{c.clean()}
});
test('live probe limits pages and rejects bad transport settings',async()=>{
 const c=envConfig('modern');try{const r=await probeStdio({configFile:c.conf,server:'sample',maxPages:1,timeoutMs:3000});
 assert.equal(r.truncated,true);assert.equal(r.toolsObserved,1);
 await assert.rejects(()=>probeStdio({configFile:c.conf,server:'sample',timeoutMs:5}),/timeoutMs/);
 }finally{c.clean()}
});
for(const [mode,expected] of [['loop',/repeated cursor/],['malformed',/tools\/list failed/],['exit',/exited/],['wrong-id',/timed out/]]){
 test(`E25 stdio probe rejects ${mode} server failure`,async()=>{
  const c=envConfig(mode);try{await assert.rejects(probeStdio({configFile:c.conf,server:'sample',timeoutMs:1500}),expected);}finally{c.clean();}
 });
}
test('CLI writes private report with no tool outputs',()=>{
 const c=envConfig('modern');try{const outfile=join(c.root,'report.json');
 const r=spawnSync(process.execPath,[cli,'compat','probe','--config',c.conf,'--server','sample','--out',outfile],{encoding:'utf8',timeout:7000});
 assert.equal(r.status,0,r.stderr);const data=JSON.parse(readFileSync(outfile));assert.equal(data.toolsObserved,2);
 if(process.platform!=='win32')assert.equal((awaitMode(outfile)&0o777),0o600);
 }finally{c.clean()}
});
function awaitMode(file){return (requireMode(file));}
import {statSync} from 'node:fs';
function requireMode(file){return statSync(file).mode;}
