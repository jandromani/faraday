import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
 symlinkSync(join(outside,'hidden.json'),join(root,'.mcp.json'));
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
test('auto install and uninstall restore exact MCP server entry with private backup',async t=>{
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
 const {installProxy,uninstallProxy}=await import('../lib/install.js');
 const root=fixture(t),file=join(root,'.mcp.json');
 writeFileSync(file,JSON.stringify({mcpServers:{sample:{command:'node',args:['example.js']}}}));
 installProxy({configFile:file,server:'sample',db:join(root,'graph.sqlite'),binPath:'/tmp/faraday.js',nodePath:process.execPath});
 const current=JSON.parse(readFileSync(file,'utf8'));current.mcpServers.sample.args[3]='changed';
 writeFileSync(file,JSON.stringify(current));
 assert.throws(()=>uninstallProxy({configFile:file,server:'sample'}),/refusing/);
});
