import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,symlinkSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {GraphStore} from '../lib/store.js';
import {ingestAdapterFile,validateAdapterRecord} from '../lib/adapter-ingest.js';
const make=()=>mkdtempSync(join(tmpdir(),'faraday-adapters-'));
const e=(o={})=>({version:1,framework:'langgraph',agent:'id-'+'a'.repeat(24),tool:'id-'+'b'.repeat(24),kind:'tool_call',status:'ok',elapsed_ms:3,...o});
test('metadata-only import is idempotent and creates graph',()=>{
  const dir=make(),db=join(dir,'graph.sqlite'),file=join(dir,'trace.jsonl');
  writeFileSync(file,JSON.stringify(e())+'\n'+JSON.stringify(e({kind:'node_call',framework:'crewai',status:'denied'}))+'\n');
  assert.equal(ingestAdapterFile({file,db}).imported,2);
  assert.equal(ingestAdapterFile({file,db}).skipped,2);
  const store=new GraphStore(db);const graph=store.snapshot();
  assert.ok(graph.nodes.some(n=>n.type==='framework'&&n.label==='crewai'));
  assert.ok(graph.edges.some(n=>n.relation==='calls_tool'));
  assert.equal(graph.stats.events,2);store.close();
});
test('reject raw arguments, unknown keys, invalid digest and dangerous files',()=>{
  assert.throws(()=>validateAdapterRecord(e({arguments:{secret:'hi'}})),/metadata-only/);
  assert.throws(()=>validateAdapterRecord(e({agent:'raw_sensitive_name'})),/record value/);
  const dir=make(),file=join(dir,'events'),alias=join(dir,'alias');
  writeFileSync(file,JSON.stringify(e({tool:'raw'}))+'\n');
  assert.throws(()=>ingestAdapterFile({file,db:join(dir,'graph.sqlite')}));
  symlinkSync(file,alias);
  assert.throws(()=>ingestAdapterFile({file:alias,db:join(dir,'graph.sqlite')}),/regular file/);
});
test('Python adapters produce events consumable by Node graph without real framework or paid model',()=>{
  const dir=make(),db=join(dir,'graph.sqlite'),trace=join(dir,'trace.jsonl');
  const script=`import sys\nsys.path.insert(0, ${JSON.stringify(new URL('../python',import.meta.url).pathname)})\nfrom faraday_adapters import Recorder,wrap_tool\nr=Recorder(${JSON.stringify(trace)})\nassert wrap_tool(lambda x:x+1,name='read',recorder=r,agent='dummy')(3)==4\n`;
  const result=spawnSync('python3',['-c',script],{encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  assert.equal(ingestAdapterFile({file:trace,db}).imported,1);
  const store=new GraphStore(db);assert.equal(store.snapshot().stats.events,1);store.close();
});
