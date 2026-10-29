import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,symlinkSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
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
test('denied or unverified adapter events do not assert execution',()=>{
  const dir=make(),db=join(dir,'graph.sqlite'),file=join(dir,'trace.jsonl');
  const events=[e({status:'denied'}),e({status:'unverified'}),e({status:'started'}),
    e({kind:'node_call',status:'denied'}),e({kind:'node_call',status:'unverified'})];
  writeFileSync(file,events.map(item=>JSON.stringify(item)).join('\n')+'\n');
  assert.equal(ingestAdapterFile({file,db}).imported,events.length);
  const store=new GraphStore(db);
  try{
    const relations=store.snapshot().edges.map(edge=>edge.relation);
    for(const relation of ['denied_tool','observes_tool','denied_node','observes_node'])assert.ok(relations.includes(relation),relation);
    assert.ok(!relations.includes('calls_tool'));assert.ok(!relations.includes('executes_node'));
    assert.equal(store.snapshot().stats.toolCalls,0);
    assert.deepEqual(new Set(store.events().map(event=>event.direction)),new Set(['denied','observed','request']));
  }finally{store.close();}
});
test('clearing graph also clears import deduplication so a trace can be reimported',()=>{
  const dir=make(),db=join(dir,'graph.sqlite'),file=join(dir,'trace.jsonl');
  writeFileSync(file,JSON.stringify(e())+'\n');
  assert.equal(ingestAdapterFile({file,db}).imported,1);
  const store=new GraphStore(db);
  try{
    assert.equal(store.clearGraph().counts.adapter_imports,1);
    assert.equal(store.clearGraph({apply:true}).counts.adapter_imports,1);
  }finally{store.close();}
  assert.equal(ingestAdapterFile({file,db}).imported,1);
  const reopened=new GraphStore(db);
  try{assert.equal(reopened.snapshot().stats.events,1);}finally{reopened.close();}
});
test('reject raw arguments, unknown keys, invalid digest and dangerous files',()=>{
  assert.throws(()=>validateAdapterRecord(e({arguments:{secret:'hi'}})),/metadata-only/);
  assert.throws(()=>validateAdapterRecord(e({agent:'raw_sensitive_name'})),/record value/);
  assert.throws(()=>validateAdapterRecord(e({agent:['id-'+'a'.repeat(24)]})),/record value/);
  assert.throws(()=>validateAdapterRecord(e({tool:['id-'+'b'.repeat(24)]})),/record value/);
  const dir=make(),file=join(dir,'events');
  writeFileSync(file,JSON.stringify(e({tool:'raw'}))+'\n');
  assert.throws(()=>ingestAdapterFile({file,db:join(dir,'graph.sqlite')}));
});
test('reject symlinked adapter files',t=>{
  const dir=make(),file=join(dir,'events'),alias=join(dir,'alias');
  writeFileSync(file,JSON.stringify(e())+'\n');
  try{symlinkSync(file,alias);}catch(error){if(process.platform==='win32'&&error.code==='EPERM'){t.skip('Windows account cannot create symbolic links');return;}throw error;}
  assert.throws(()=>ingestAdapterFile({file:alias,db:join(dir,'graph.sqlite')}),/regular file/);
});
test('all Python adapters produce metadata consumable by Node without real SDKs or models',()=>{
  const dir=make(),db=join(dir,'graph.sqlite'),trace=join(dir,'trace.jsonl');
  const script=`import sys, asyncio, types\nsys.path.insert(0, ${JSON.stringify(fileURLToPath(new URL('../python',import.meta.url)))})\nfrom faraday_adapters import Recorder,wrap_tool,wrap_node,make_tool_hooks,make_function_tool\nr=Recorder(${JSON.stringify(trace)})\nassert wrap_tool(lambda x:x+1,name='read',recorder=r,agent='dummy')(3)==4\nassert wrap_node(lambda state:state,name='node',recorder=r)({'secret':'PRIVATE_VALUE'})=={'secret':'PRIVATE_VALUE'}\nbefore,after=make_tool_hooks(recorder=r,allowed_tools={'read'})\nctx=types.SimpleNamespace(tool_name='write',agent=types.SimpleNamespace(role='crew'))\nassert before(ctx) is False\nafter(ctx)\nclass FunctionTool:\n def __init__(self,**kwargs): self.__dict__.update(kwargs)\nsys.modules['agents']=types.SimpleNamespace(FunctionTool=FunctionTool)\ntool=make_function_tool(lambda text:text,name='echo',params_json_schema={'type':'object'},recorder=r)\nassert asyncio.run(tool.on_invoke_tool(None,'{"text":"PRIVATE_VALUE"}'))=='PRIVATE_VALUE'\n`;
  const result=spawnSync(process.env.FARADAY_PYTHON||'python3',['-c',script],{encoding:'utf8'});
  assert.ifError(result.error);
  assert.equal(result.status,0,result.stderr);
  assert.equal(ingestAdapterFile({file:trace,db}).imported,5);
  assert.equal(ingestAdapterFile({file:trace,db}).skipped,5);
  const store=new GraphStore(db),graph=store.snapshot();
  assert.equal(graph.stats.events,5);
  assert.deepEqual(graph.nodes.filter(node=>node.type==='framework').map(node=>node.label).sort(),['crewai','langgraph','openai-agents']);
  assert.ok(!JSON.stringify(graph).includes('PRIVATE_VALUE'));store.close();
});
