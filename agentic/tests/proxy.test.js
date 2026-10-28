import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { GraphStore } from '../lib/store.js';
const cli=resolve('bin/faraday.js'),server=resolve('tests/fixture_server.js');
function setup(t){const dir=mkdtempSync(join(tmpdir(),'faraday-proxy-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const config=join(dir,'.mcp.json'),db=join(dir,'graph.sqlite');
 writeFileSync(config,JSON.stringify({mcpServers:{fixture:{command:process.execPath,args:[server],env:{API_KEY:'SECRET_DO_NOT_LOG'}}}}));
 return {dir,config,db};}
function interact(proc, requests, expected, timeout=8000){return new Promise((resolve,reject)=>{
 let buf='',got=[],done=false;
 const timer=setTimeout(()=>{if(!done){done=true;proc.kill();reject(Error('Timed out'));}},timeout);
 proc.stdout.on('data',chunk=>{
   buf+=chunk.toString('utf8');let n;
   while((n=buf.indexOf('\n'))!==-1){const line=buf.slice(0,n);buf=buf.slice(n+1);
     if(line.trim())try{got.push(JSON.parse(line));}catch{done=true;clearTimeout(timer);reject(Error('Non-JSON stdout'));return;}
   }
   if(!done&&got.length>=expected){done=true;clearTimeout(timer);proc.stdin.end();resolve(got);}
 });
 proc.on('error',e=>{if(!done){done=true;clearTimeout(timer);reject(e);}});
 for(const m of requests)proc.stdin.write(JSON.stringify(m)+'\n');
});}

test('transparent stdio bridge logs tool metadata and preserves all original MCP frames',async t=>{
 const {config,db}=setup(t);
 const proc=spawn(process.execPath,[cli,'proxy','--config',config,'--server','fixture','--db',db],{stdio:['pipe','pipe','pipe']});
 t.after(()=>{if(!proc.killed)proc.kill();});
 const requests=[
 {jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-06-18',capabilities:{},clientInfo:{name:'test',version:'0'}}},
 {jsonrpc:'2.0',method:'notifications/initialized'},
 {jsonrpc:'2.0',id:2,method:'tools/list'},
 {jsonrpc:'2.0',id:3,method:'tools/call',params:{name:'echo',arguments:{secret:'SECRET_DO_NOT_LOG'}}},
 {jsonrpc:'2.0',id:4,method:'tools/call',params:{name:'error',arguments:{sensitive:'SECRET_DO_NOT_LOG'}}},
 ];
 const out=await interact(proc,requests,4);
 assert.deepEqual(out.map(m=>m.id),[1,2,3,4]);
 assert.equal(out[1].result.tools.length,2);
 assert.ok(out[2].result.content[0].text.includes('SECRET_DO_NOT_LOG'));
 assert.equal(out[3].result.isError,true);
 await new Promise((resolve)=>proc.once('close',resolve));
 const store=new GraphStore(db),graph=store.snapshot(),events=store.events(50);
 assert.ok(graph.nodes.some(n=>n.type==='tool'&&n.label==='echo'));
 assert.equal(graph.stats.contracts,2);
 assert.equal(store.contracts().find(c=>c.tool==='echo')?.server,'fixture');
 assert.equal(graph.stats.toolCalls,2);
 assert.ok(events.some(e=>e.status==='error'&&e.operation==='tools/call'));
 assert.ok(events.some(e=>e.operation==='notifications/initialized'));
 assert.ok(!JSON.stringify({graph,events}).includes('SECRET_DO_NOT_LOG'));
 store.close();
});
test('non-executing CLI scan persists config metadata only',async t=>{
 const {config,db,dir}=setup(t);
 const args=[cli,'scan','--root',dir,'--db',db,'--json'];
 const proc=spawn(process.execPath,args,{stdio:['ignore','pipe','pipe']});
 let output='';for await(const chunk of proc.stdout)output+=chunk;
 const code=await new Promise(resolve=>proc.on('close',resolve));
 assert.equal(code,0);
 const report=JSON.parse(output);assert.equal(report.servers.length,1);
 assert.ok(!output.includes('SECRET_DO_NOT_LOG'));
 const store=new GraphStore(db);assert.equal(store.snapshot().stats.events,0);store.close();
});
test('hook emits a usable wrapper without altering the original configuration',async t=>{
 const {config,db}=setup(t);
 const before=readFileSync(config,'utf8');
 const proc=spawn(process.execPath,[cli,'hook','--config',config,'--server','fixture','--db',db],{stdio:['ignore','pipe','pipe']});
 let output='';for await(const chunk of proc.stdout)output+=chunk;
 const status=await new Promise(resolve=>proc.once('close',resolve));
 assert.equal(status,0);
 const hook=JSON.parse(output);
 assert.equal(hook.command,process.execPath);assert.ok(hook.args.includes('proxy'));
 assert.equal(readFileSync(config,'utf8'),before);
 assert.ok(!output.includes('SECRET_DO_NOT_LOG'));
});
test('one-command demo creates a graph with live MCP interactions',async t=>{
 const {dir,db}=setup(t);
 const proc=spawn(process.execPath,[cli,'demo','--db',db],{cwd:dir,stdio:['ignore','pipe','pipe']});
 let output='';for await(const chunk of proc.stdout)output+=chunk.toString();
 const code=await new Promise(resolve=>proc.once('close',resolve));
 assert.equal(code,0);assert.match(output,/2 tool calls/);
 const store=new GraphStore(db);assert.equal(store.snapshot().stats.toolCalls,2);store.close();
});
