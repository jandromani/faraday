import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { discover, configServers, safeLabel, getExecutableServer } from '../lib/discover.js';
import { GraphStore, toMermaid } from '../lib/store.js';

function fixture(t) {const dir=mkdtempSync(join(tmpdir(),'faraday-discover-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));return dir;}

test('supports both MCP client config layouts and HTTP/stdio',t=>{
 const dir=fixture(t);mkdirSync(join(dir,'.vscode'),{recursive:true});
 writeFileSync(join(dir,'.mcp.json'),JSON.stringify({mcpServers:{alpha:{command:'node',args:['server.js'],env:{API_KEY:'SECRET_DO_NOT_LOG'}}}}));
 writeFileSync(join(dir,'.vscode/mcp.json'),JSON.stringify({servers:{remote:{type:'http',url:'https://mcp.example.org/mcp?token=SECRET_DO_NOT_LOG'}}}));
 const report=discover({root:dir});
 assert.equal(report.servers.length,2);
 assert.deepEqual(report.servers.map(s=>s.transport).sort(),['http','stdio']);
 assert.ok(!JSON.stringify(report.servers).includes('SECRET_DO_NOT_LOG'));
 assert.ok(!JSON.stringify(report.servers).includes('https://'));
 assert.equal(report.warnings.length,0);
 const store=new GraphStore(join(dir,'.faraday','graph.sqlite'));
 store.inventory(report.servers);
 assert.equal(store.snapshot().nodes.length,6);
 assert.match(toMermaid(store.snapshot()),/flowchart LR/);
 store.close();
});
test('nonexistent and malformed JSON reports safely without throwing',t=>{
 const dir=fixture(t);writeFileSync(join(dir,'.mcp.json'),'{bad json SECRET_DO_NOT_LOG');
 const report=discover({root:dir});assert.equal(report.servers.length,0);
 assert.equal(report.warnings.length,1);
 assert.ok(!JSON.stringify(report).includes('SECRET_DO_NOT_LOG'));
});
test('workspace symlink outside root is not followed',t=>{
 const root=fixture(t),outside=fixture(t);
 writeFileSync(join(outside,'hidden.json'),JSON.stringify({mcpServers:{stolen:{command:'node'}}}));
 try{symlinkSync(join(outside,'hidden.json'),join(root,'.mcp.json'));}catch(error){if(process.platform==='win32'&&error.code==='EPERM'){t.skip('Windows account cannot create symbolic links');return;}throw error;}
 const report=discover({root});assert.equal(report.servers.length,0);assert.match(report.warnings[0],/symlink/);
});
test('global configs remain opt-in',t=>{
 const root=fixture(t),home=fixture(t),file=join(home,'global.json');
 writeFileSync(file,JSON.stringify({mcpServers:{personal:{command:'node'}}}));
 assert.equal(discover({root,globalEntries:[['cursor-global',file]]}).servers.length,0);
 assert.equal(discover({root,includeGlobal:true,globalEntries:[['cursor-global',file]]}).servers.length,1);
});
test('safe labels redact token-like and unsafe strings',()=>{
 assert.equal(safeLabel('echo'),'echo');
 assert.match(safeLabel('sk-SECRET_DO_NOT_LOG'),/^redacted-/);
 assert.match(safeLabel('TOKEN_NAME'),/^redacted-/);
 assert.match(safeLabel('";DROP TABLE events'),/^redacted-/);
});
test('proxy refuses direct HTTP and malformed server executable',t=>{
 const root=fixture(t),config=join(root,'.mcp.json');
 writeFileSync(config,JSON.stringify({mcpServers:{remote:{url:'https://example.com'},broken:{command:'node',args:[42]}}}));
 assert.throws(()=>getExecutableServer(config,'remote'),/stdio/);
 assert.throws(()=>getExecutableServer(config,'broken'),/Invalid stdio/);
});
test('graph metadata schema and counts persist across reopen',t=>{
 const root=fixture(t),db=join(root,'graph.sqlite');
 const store=new GraphStore(db);store.inventory([{client:'claude-code',server:'search',transport:'stdio'}]);
 store.tool('search','fetch');store.event({server:'search',direction:'response',kind:'tool_call',operation:'tools/call',tool:'fetch',status:'ok',latencyMs:3});
 store.close();
 const again=new GraphStore(db);const snap=again.snapshot();
 assert.equal(snap.nodes.length,4);assert.equal(snap.stats.toolCalls,1);
 assert.equal(again.events()[0].tool,'fetch');again.close();
});
test('graph refuses dangling database links',t=>{
 const root=fixture(t),target=join(root,'missing'),db=join(root,'graph.sqlite');
 try{symlinkSync(target,db,process.platform==='win32'?'junction':'file');}
 catch(error){if(process.platform==='win32'&&error.code==='EPERM'){t.skip('Windows account cannot create symbolic links');return;}throw error;}
 assert.throws(()=>new GraphStore(db),/Unsafe graph database path/);
 assert.equal(existsSync(target),false);
});
test('graph event retention previews and deletes only events before an explicit UTC cutoff',t=>{
 const root=fixture(t),store=new GraphStore(join(root,'graph.sqlite'));
 try{
  store.event({server:'demo',direction:'response',kind:'tool_call',operation:'tools/call'});
  store.event({server:'demo',direction:'response',kind:'tool_call',operation:'tools/call'});
  store.db.prepare('UPDATE events SET ts=? WHERE id=1').run('2025-01-01T00:00:00.000Z');
  store.db.prepare('UPDATE events SET ts=? WHERE id=2').run('2026-01-01T00:00:00.000Z');
  const cutoff='2026-01-01T00:00:00.000Z';
  assert.deepEqual(store.pruneEventsBefore(cutoff),{before:cutoff,matched:1,deleted:0,applied:false});
  assert.equal(store.snapshot().stats.events,2);
  assert.throws(()=>store.pruneEventsBefore('2026-01-01'),/UTC timestamp/);
  assert.throws(()=>store.pruneEventsBefore('2026-02-30T00:00:00.000Z'),/Invalid/);
  assert.deepEqual(store.pruneEventsBefore(cutoff,{apply:true}),{before:cutoff,matched:1,deleted:1,applied:true});
  assert.equal(store.snapshot().stats.events,1);
 }finally{store.close();}
});
test('graph prune CLI previews by default and requires an existing explicit database',t=>{
 const root=fixture(t),db=join(root,'graph.sqlite'),store=new GraphStore(db),cli=fileURLToPath(new URL('../bin/faraday.js',import.meta.url));
 store.event({server:'demo',direction:'response',kind:'tool_call',operation:'tools/call'});
 store.db.prepare('UPDATE events SET ts=?').run('2025-01-01T00:00:00.000Z');store.close();
 const run=args=>spawnSync(process.execPath,[cli,'graph','prune',...args],{encoding:'utf8'});
 const args=['--db',db,'--before','2026-01-01T00:00:00.000Z'];
 const preview=run(args);assert.ifError(preview.error);assert.equal(preview.status,0,preview.stderr);assert.deepEqual(JSON.parse(preview.stdout),{before:args[3],matched:1,deleted:0,applied:false});
 const applied=run([...args,'--apply']);assert.ifError(applied.error);assert.equal(applied.status,0,applied.stderr);assert.equal(JSON.parse(applied.stdout).deleted,1);
 assert.notEqual(run(['--before',args[3],'--apply']).status,0);
 assert.notEqual(run(['--db',join(root,'missing.sqlite'),'--before',args[3]]).status,0);
 assert.equal(existsSync(join(root,'missing.sqlite')),false);
});
test('Windows auto-install refuses before creating a credential backup', {skip:process.platform!=='win32'},async t=>{
 const {installProxy}=await import('../lib/install.js');
 const root=fixture(t),file=join(root,'.mcp.json');
 const original=JSON.stringify({mcpServers:{tool:{command:process.execPath,env:{AUTH:'SECRET_DO_NOT_LOG'}}}});
 writeFileSync(file,original);
 const options={configFile:file,server:'tool',db:join(root,'graph.sqlite'),binPath:'faraday.js',nodePath:process.execPath};
 assert.equal(installProxy({...options,dryRun:true}).changed,false);
 assert.throws(()=>installProxy(options),/backup ACL protection is not verified/);
 assert.equal(readFileSync(file,'utf8'),original);
 assert.equal(existsSync(join(root,'.faraday')),false);
});
test('auto install and uninstall restore exact MCP server entry with private backup',{skip:process.platform==='win32'?'Windows backup ACL protection is not verified':false},async t=>{
 const {installProxy,uninstallProxy}=await import('../lib/install.js');
 const {statSync,readFileSync}=await import('node:fs');
 const root=fixture(t),file=join(root,'.mcp.json'),db=join(root,'graph.sqlite');
 const original={mcpServers:{tool:{command:process.execPath,args:['sample.js'],env:{AUTH:'SECRET_DO_NOT_LOG'}},other:{url:'https://example.org'}}};
 writeFileSync(file,JSON.stringify(original));
 const out=installProxy({configFile:file,server:'tool',db,binPath:'/tmp/faraday.js',nodePath:process.execPath});
 assert.equal(statSync(out.backup).mode&0o777,0o600);
 assert.equal(getExecutableServer(out.backup,'tool').env.AUTH,'SECRET_DO_NOT_LOG');
 const wrapped=JSON.parse(readFileSync(file,'utf8'));
 assert.equal(wrapped.mcpServers.tool.args[1],'proxy');
 assert.deepEqual(wrapped.mcpServers.other,original.mcpServers.other);
 assert.throws(()=>installProxy({configFile:file,server:'tool',db,binPath:'/tmp/faraday.js',nodePath:process.execPath}),/Already installed/);
 uninstallProxy({configFile:file,server:'tool'});
 assert.deepEqual(JSON.parse(readFileSync(file,'utf8')),original);
 assert.ok(!existsSync(out.backup));
});
test('uninstall refuses to overwrite a manually edited wrapper',async t=>{
 const {uninstallProxy}=await import('../lib/install.js');
 const root=fixture(t),file=join(root,'.mcp.json');
 const target=join(root,'.faraday','targets');mkdirSync(target,{recursive:true});
 const id=createHash('sha256').update(file+'\0sample').digest('hex').slice(0,24),backup=join(target,id+'.json');
 writeFileSync(backup,JSON.stringify({mcpServers:{sample:{command:'node',args:['example.js']}}}));
 writeFileSync(file,JSON.stringify({mcpServers:{sample:{command:process.execPath,args:['faraday.js','proxy','--config','changed']}}}));
 assert.throws(()=>uninstallProxy({configFile:file,server:'sample'}),/refusing/);
});
