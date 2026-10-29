import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, mkdirSync, symlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { GraphStore } from '../lib/store.js';
import { normalizeSchema, snapshotFromStore, compareSnapshots, saveSnapshot, generateRegressionTests } from '../lib/contracts.js';
import { doctor, initialize } from '../lib/setup.js';

const workspace=t=>{const dir=mkdtempSync(join(tmpdir(),'faraday-contracts-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));return dir;};
const tool=(inputSchema, outputSchema=null, other={})=>({server:'s',tool:'t',inputSchema,outputSchema,potentialClients:['cursor'],fingerprint:'placeholder',...other});
const snapshot=tools=>({format:'faraday-contract-snapshot',version:1,coverage:'observed-tools-list',tools});
const schema=(props,required=[])=>normalizeSchema({type:'object',properties:props,required});
const standaloneEnv={...process.env};delete standaloneEnv.NODE_TEST_CONTEXT;
const linkLocalPackage=dir=>{const pkgDir=join(dir,'node_modules','@faraday');mkdirSync(pkgDir,{recursive:true});symlinkSync(resolve('.'),join(pkgDir,'agentic'),process.platform==='win32'?'junction':'dir');};
const launch=(args,cwd)=>spawnSync(process.execPath,[resolve('bin/faraday.js'),...args],{cwd,encoding:'utf8',timeout:8000});

test('contract normalization eliminates descriptions, defaults, enum literals, credentials and examples',()=>{
  const input={type:'object',description:'SECRET_SENTINEL',properties:{message:{type:'string',default:'SECRET_SENTINEL',enum:['SECRET_SENTINEL'],examples:['SECRET_SENTINEL']},api_key:{type:'string'}}};
  const normalized=normalizeSchema(input);
  assert.ok(!JSON.stringify(normalized).includes('SECRET_SENTINEL'));
  assert.ok(!JSON.stringify(normalized).includes('api_key'));
  assert.equal(normalized.properties.message.types[0],'string');
  assert.ok(normalized.properties.message.unmodeled);
});
test('observed contracts persist without secret schema bodies and link potential clients',t=>{
  const dir=workspace(t),db=join(dir,'graph.sqlite');
  let store=new GraphStore(db);
  store.inventory([{client:'cursor',server:'s',transport:'stdio'}]);
  store.contract('s','t',{type:'object',description:'SECRET_SENTINEL',properties:{message:{type:'string',default:'SECRET_SENTINEL'}}});
  store.close();store=new GraphStore(db);
  const snap=snapshotFromStore(store);
  assert.deepEqual(snap.tools[0].potentialClients,['cursor']);
  assert.equal(store.snapshot().stats.contracts,1);
  assert.ok(!JSON.stringify(snap).includes('SECRET_SENTINEL'));
  assert.ok(!readFileSync(db).includes(Buffer.from('SECRET_SENTINEL')));
  store.close();
});
test('required property added is breaking',()=>{
  const base=snapshot([tool(schema({id:{type:'string'}}))]);
  const changed=snapshot([tool(schema({id:{type:'string'},auth:{type:'string'}},['auth']))]);
  assert.ok(compareSnapshots(base,changed).summary.breaking>0);
});
test('removed tool or property is breaking',()=>{
  const base=snapshot([tool(schema({id:{type:'string'}}))]);
  assert.ok(compareSnapshots(base,snapshot([])).summary.breaking>0);
  assert.ok(compareSnapshots(base,snapshot([tool(schema({}))])).summary.breaking>0);
});
test('type narrowing and additionalProperties tightening are breaking',()=>{
  const initial=normalizeSchema({type:'object',additionalProperties:true,properties:{id:{type:['string','null']}}});
  const changed=normalizeSchema({type:'object',additionalProperties:false,properties:{id:{type:'string'}}});
  const diff=compareSnapshots(snapshot([tool(initial)]),snapshot([tool(changed)]));
  assert.ok(diff.summary.breaking>=2);
});
test('optional property addition and widened type are additive',()=>{
  const initial=schema({id:{type:'string'}}),changed=schema({id:{type:['string','null']},note:{type:'string'}});
  const diff=compareSnapshots(snapshot([tool(initial)]),snapshot([tool(changed)]));
  assert.equal(diff.summary.breaking,0);
  assert.ok(diff.summary.additive>=2);
});
test('output schema changes are conservatively flagged for review',()=>{
  const diff=compareSnapshots(snapshot([tool(schema({}),schema({x:{type:'string'}}))]),snapshot([tool(schema({}),schema({x:{type:'number'}}))]));
  assert.ok(diff.summary.review>0);
});
test('absent changes in unmodeled values cannot be detected (documented coverage)',()=>{
  const before=normalizeSchema({type:'string',enum:['a']});
  const after=normalizeSchema({type:'string',enum:['b']});
  assert.deepEqual(before,after);
  assert.equal(before.unmodeled,true);
});
test('snapshot export + compare + generated node tests work offline',t=>{
  const dir=workspace(t),db=join(dir,'graph.sqlite');
  const store=new GraphStore(db);store.contract('s','t',{type:'object',properties:{id:{type:'string'}}});
  const base=join(dir,'baseline.json'),current=join(dir,'current.json');
  saveSnapshot(base,snapshotFromStore(store));store.contract('s','t',{type:'object',properties:{id:{type:'string'},optional:{type:'number'}}});
  saveSnapshot(current,snapshotFromStore(store));store.close();
  linkLocalPackage(dir);
  const exported=join(dir,'.faraday','regression');
  const out=generateRegressionTests({baseline:base,current,outDir:exported});
  assert.equal(out.breaking,0);
  assert.equal(launch(['contracts','compare','--base',base,'--current',current,'--fail-on-breaking'],dir).status,0);
  const testRun=spawnSync(process.execPath,['--test',join(exported,'contracts.regression.test.mjs')],{cwd:resolve('.'),encoding:'utf8',env:standaloneEnv});
  assert.equal(testRun.status,0,testRun.stderr+'\n'+testRun.stdout);
});
test('generated tests fail on breaking snapshots',t=>{
  const dir=workspace(t),base=join(dir,'b.json'),current=join(dir,'c.json');
  saveSnapshot(base,snapshot([tool(schema({id:{type:'string'}}))]));
  saveSnapshot(current,snapshot([]));
  linkLocalPackage(dir);
  const out=generateRegressionTests({baseline:base,current,outDir:join(dir,'.faraday','regression')});
  assert.equal(out.breaking,1);
  assert.equal(launch(['contracts','compare','--base',base,'--current',current,'--fail-on-breaking'],dir).status,2);
  const status=spawnSync(process.execPath,['--test',join(out.dir,'contracts.regression.test.mjs')],{cwd:resolve('.'),encoding:'utf8',env:standaloneEnv});
  assert.notEqual(status.status,0);
});
test('init --dry-run does not write and init is idempotent',t=>{
  const dir=workspace(t);writeFileSync(join(dir,'.mcp.json'),JSON.stringify({mcpServers:{demo:{command:'node',args:['index.js']}}}));
  const plan=initialize({root:dir,dryRun:true});
  assert.equal(plan.dryRun,true);assert.ok(!existsSync(join(dir,'.gitignore')));
  const first=initialize({root:dir});assert.ok(existsSync(first.db));
  initialize({root:dir});
  assert.equal(readFileSync(join(dir,'.gitignore'),'utf8').match(/\.faraday\//g).length,1);
  const health=doctor({root:dir});assert.ok(health.ready);assert.equal(health.servers.length,1);
});
test('init refuses unsafe linked .faraday directory',t=>{
  const dir=workspace(t),outside=workspace(t);
  symlinkSync(outside,join(dir,'.faraday'),process.platform==='win32'?'junction':'dir');
  assert.throws(()=>initialize({root:dir}),/Unsafe/);
});
test('init refuses unsafe symlinked .gitignore',t=>{
  const dir=workspace(t),outside=workspace(t);
  writeFileSync(join(outside,'ignore'),'#unsafe');
  try{symlinkSync(join(outside,'ignore'),join(dir,'.gitignore'));}catch(error){if(process.platform==='win32'&&error.code==='EPERM'){t.skip('Windows account cannot create symbolic links');return;}throw error;}
  assert.throws(()=>initialize({root:dir}),/Unsafe/);
});
test('CLI doctor output never reveals config env values',t=>{
  const dir=workspace(t);writeFileSync(join(dir,'.mcp.json'),JSON.stringify({mcpServers:{tool:{command:'node',env:{TOKEN:'SECRET_SENTINEL'}}}}));
  const proc=launch(['doctor','--root',dir,'--json'],dir);
  assert.equal(proc.status,0,proc.stderr);
  assert.ok(!proc.stdout.includes('SECRET_SENTINEL'));
});
test('complete tools/list replaces contracts while preserving graph history',t=>{
  const dir=workspace(t),store=new GraphStore(join(dir,'graph.sqlite'));
  store.replaceContracts('s',[{name:'a',inputSchema:{type:'object'}},{name:'b',inputSchema:{type:'object'}}]);
  const old=snapshotFromStore(store);
  store.replaceContracts('s',[{name:'b',inputSchema:{type:'object'}}]);
  const now=snapshotFromStore(store);store.close();
  assert.equal(old.tools.length,2);assert.equal(now.tools.length,1);
  assert.equal(compareSnapshots(old,now).summary.breaking,1);
});
test('observer paged tools/list does not prematurely remove contracts',t=>{
  const dir=workspace(t),store=new GraphStore(join(dir,'graph.sqlite'));
  store.replaceContracts('test',[{name:'existing',inputSchema:{type:'object'}}]);
  return import('../lib/observe.js').then(({McpObserver})=>{
    const observer=new McpObserver(store,'test');
    observer.consume(JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'}),'client_to_server');
    observer.consume(JSON.stringify({jsonrpc:'2.0',id:1,result:{tools:[{name:'page1',inputSchema:{type:'object'}}],nextCursor:'sensitive-page-cursor'}}),'server_to_client');
    assert.deepEqual(store.contracts().map(x=>x.tool),['existing']);
    observer.consume(JSON.stringify({jsonrpc:'2.0',id:2,method:'tools/list',params:{cursor:'sensitive-page-cursor'}}),'client_to_server');
    observer.consume(JSON.stringify({jsonrpc:'2.0',id:2,result:{tools:[{name:'page2',inputSchema:{type:'object'}}]}}),'server_to_client');
    assert.deepEqual(store.contracts().map(x=>x.tool),['page1','page2']);
    assert.ok(!JSON.stringify(snapshotFromStore(store)).includes('sensitive-page-cursor'));
    store.close();
  });
});
test('observer discards mismatched cursors and stale overlapping listings',async t=>{
  const dir=workspace(t),store=new GraphStore(join(dir,'graph.sqlite'));
  try{
  store.replaceContracts('test',[{name:'existing',inputSchema:{type:'object'}}]);
  const {McpObserver}=await import('../lib/observe.js'),observer=new McpObserver(store,'test');
  const request=(id,cursor)=>observer.consume(JSON.stringify({jsonrpc:'2.0',id,method:'tools/list',...(cursor===undefined?{}:{params:{cursor}})}),'client_to_server');
  const response=(id,name,nextCursor)=>observer.consume(JSON.stringify({jsonrpc:'2.0',id,result:{tools:[{name,inputSchema:{type:'object'}}],...(nextCursor===undefined?{}:{nextCursor})}}),'server_to_client');
  request(1);response(1,'first','expected');request(2,'different');response(2,'wrong');
  assert.deepEqual(store.contracts().map(x=>x.tool),['existing']);
  request(6);response(6,'first','expected');request(7,'expected');
  observer.consume(JSON.stringify({jsonrpc:'2.0',id:7,error:{code:-32603,message:'failed'}}),'server_to_client');
  request(8,'expected');response(8,'late');
  assert.deepEqual(store.contracts().map(x=>x.tool),['existing']);
  request(3);request(4);response(4,'new','next');response(3,'stale');
  assert.deepEqual(store.contracts().map(x=>x.tool),['existing']);
  request(5,'next');response(5,'final');
  assert.deepEqual(store.contracts().map(x=>x.tool),['final','new']);
  }finally{store.close();}
});
test('observer discards repeated and cyclic pagination cursors',async t=>{
  const dir=workspace(t),store=new GraphStore(join(dir,'graph.sqlite'));
  try{
    store.replaceContracts('test',[{name:'existing',inputSchema:{type:'object'}}]);
    const {McpObserver}=await import('../lib/observe.js'),observer=new McpObserver(store,'test');
    const request=(id,cursor)=>observer.consume(JSON.stringify({jsonrpc:'2.0',id,method:'tools/list',...(cursor===undefined?{}:{params:{cursor}})}),'client_to_server');
    const response=(id,name,nextCursor)=>observer.consume(JSON.stringify({jsonrpc:'2.0',id,result:{tools:[{name,inputSchema:{type:'object'}}],...(nextCursor===undefined?{}:{nextCursor})}}),'server_to_client');
    request(1);response(1,'first','cursor-a');request(2,'cursor-a');response(2,'repeat','cursor-a');
    request(3,'cursor-a');response(3,'incomplete');
    assert.deepEqual(store.contracts().map(row=>row.tool),['existing']);
    request(4);response(4,'first','cursor-a');request(5,'cursor-a');response(5,'second','cursor-b');
    request(6,'cursor-b');response(6,'cycle','cursor-a');request(7,'cursor-a');response(7,'incomplete');
    assert.deepEqual(store.contracts().map(row=>row.tool),['existing']);
    request(8);response(8,'first','cursor-a');request(9,'cursor-a');response(9,'last');
    assert.deepEqual(store.contracts().map(row=>row.tool),['first','last']);
  }finally{store.close();}
});
