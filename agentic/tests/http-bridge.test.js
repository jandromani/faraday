import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { configuredHttpServer, HttpBridge } from '../lib/http-bridge.js';
import { GraphStore } from '../lib/store.js';
import { installProxy, uninstallProxy } from '../lib/install.js';

const CLI=resolve('bin/faraday.js');
const META={'io.modelcontextprotocol/protocolVersion':'2026-07-28',
            'io.modelcontextprotocol/clientInfo':{name:'test',version:'1'},
            'io.modelcontextprotocol/clientCapabilities':{}};
const rpc = (id, method, params={}) => ({jsonrpc:'2.0',id,method,params:{...params,_meta:META}});
const init = rpc(1,'initialize',{protocolVersion:'2026-07-28',capabilities:{},clientInfo:{name:'test',version:'1'}});
const LIST = [{name:'echo',inputSchema:{type:'object',properties:{value:{type:'string'},region:{type:'string','x-mcp-header':'Region'}},required:['value']}}];
function workspace(t) {
  const dir=mkdtempSync(join(tmpdir(),'faraday-http-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
  return {dir,db:join(dir,'graph.sqlite'),config:join(dir,'mcp.json')};
}
async function fixture(t,{sse=true,redirect=false}={}) {
  const seen=[];
  const app=createServer(async(req,res)=>{
    let body='';for await (const chunk of req) body+=chunk;
    const m=JSON.parse(body);seen.push({m,headers:req.headers});
    if(redirect) {res.writeHead(302,{location:'http://attacker.invalid/leak'}).end();return;}
    if(req.headers.authorization!=='Bearer DEV_SECRET_DO_NOT_PERSIST'){
      res.writeHead(403).end();return;
    }
    const json = (obj,session=false) => {
      res.writeHead(200,{'content-type':'application/json',...(session?{'mcp-session-id':'DEMO-session-id'}:{})});
      res.end(JSON.stringify(obj));
    };
    if(m.method==='initialize')return json({jsonrpc:'2.0',id:m.id,result:{protocolVersion:'2026-07-28',capabilities:{tools:{}},serverInfo:{name:'fixture',version:'1'}}},true);
    if(m.method==='notifications/initialized') {res.writeHead(202).end();return;}
    if(m.method==='tools/list') {
      const response={jsonrpc:'2.0',id:m.id,result:{tools:LIST}};
      if(sse){res.writeHead(200,{'content-type':'text/event-stream'});res.end(': comment\n\nevent: message\ndata: '+JSON.stringify(response)+'\n\n');}
      else json(response);
      return;
    }
    if(m.method==='tools/call') return json({jsonrpc:'2.0',id:m.id,result:{content:[{type:'text',text:'DEV_SECRET_DO_NOT_PERSIST'}]}});
    json({jsonrpc:'2.0',id:m.id,error:{code:-32601,message:'Not implemented'}});
  });
  await new Promise(r=>app.listen(0,'127.0.0.1',r));
  t.after(()=>app.close());
  return {url:`http://127.0.0.1:${app.address().port}/mcp`,seen};
}
const config=(url, headers={'Authorization':'Bearer DEV_SECRET_DO_NOT_PERSIST'})=>({mcpServers:{remote:{type:'http',url,headers}}});

async function waitForOutput(proc, count) {
  return await new Promise((resolve,reject)=>{
    let done=false,buffer='',out=[];
    const timer=setTimeout(()=>{if(!done){done=true;proc.kill();reject(Error('bridge timeout'));}},7000);
    proc.stdout.on('data',chunk=>{
      buffer+=chunk.toString();let nl;
      while((nl=buffer.indexOf('\n'))>=0){
        const line=buffer.slice(0,nl);buffer=buffer.slice(nl+1);
        if(!line.trim())continue;
        try{out.push(JSON.parse(line));}catch(e){done=true;clearTimeout(timer);reject(e);return;}
      }
      if(!done&&out.length>=count){done=true;clearTimeout(timer);resolve(out);}
    });
    proc.once('error',reject);
  });
}

test('HTTP bridge forwards JSON and SSE, persists contracts and redacts content',async t=>{
  const {db,config:conf}=workspace(t),fx=await fixture(t);
  writeFileSync(conf,JSON.stringify(config(fx.url)));
  const server=configuredHttpServer(conf,'remote');
  const lines=[];
  const bridge=new HttpBridge({server,db,emit:raw=>lines.push(raw)});
  await bridge.accept(JSON.stringify(init));
  await bridge.accept(JSON.stringify(rpc(2,'tools/list')));
  await bridge.accept(JSON.stringify(rpc(3,'tools/call',{name:'echo',arguments:{value:'SENSITIVE_ARG_DO_NOT_PERSIST',region:'eu-west-1'}})));
  await bridge.close();
  const responses=lines.map(x=>JSON.parse(x));
  assert.deepEqual(responses.map(r=>r.id),[1,2,3]);
  assert.equal(responses[1].result.tools[0].name,'echo');
  assert.equal(fx.seen[2].headers['mcp-name'],'echo');
  assert.equal(fx.seen[2].headers['mcp-method'],'tools/call');
  assert.equal(fx.seen[2].headers['mcp-param-region'],'eu-west-1');
  assert.equal(fx.seen[2].headers['mcp-session-id'],'DEMO-session-id');
  const store=new GraphStore(db);
  const serial=JSON.stringify({graph:store.snapshot(),events:store.events(),contracts:store.contracts()});
  assert.equal(store.snapshot().stats.toolCalls,1);
  assert.equal(store.snapshot().stats.contracts,1);
  assert.ok(!serial.includes('DEV_SECRET_DO_NOT_PERSIST') && !serial.includes('SENSITIVE_ARG_DO_NOT_PERSIST'));
  store.close();
});

test('HTTP bridge launched as CLI subprocess can handle real JSON-RPC stdio',async t=>{
  const {db,config:conf}=workspace(t),fx=await fixture(t,{sse:false});
  writeFileSync(conf,JSON.stringify(config(fx.url)));
  const proc=spawn(process.execPath,[CLI,'bridge','--config',conf,'--server','remote','--db',db],{stdio:['pipe','pipe','pipe']});
  t.after(()=>{if(!proc.killed)proc.kill();});
  const expected=waitForOutput(proc,2);
  proc.stdin.write(JSON.stringify(init)+'\n');
  proc.stdin.write(JSON.stringify(rpc(2,'tools/list'))+'\n');
  const responses=await expected;
  assert.deepEqual(responses.map(x=>x.id),[1,2]);
  proc.stdin.end();
  assert.equal(await new Promise(r=>proc.once('close',r)),0);
  const store=new GraphStore(db);assert.equal(store.snapshot().stats.contracts,1);store.close();
});

test('install/uninstall converts HTTP to stdio shim, restores exact config entry; dry-run does not write',async t=>{
  const {db,config:conf}=workspace(t),fx=await fixture(t);
  const data=config(fx.url);
  writeFileSync(conf,JSON.stringify(data,null,2));
  const original=readFileSync(conf,'utf8');
  const opts={configFile:conf,server:'remote',db,binPath:CLI,nodePath:process.execPath};
  assert.equal(installProxy({...opts,dryRun:true}).changed,false);
  assert.equal(readFileSync(conf,'utf8'),original);
  const result=installProxy(opts);
  assert.equal(result.transport,'http');
  const active=JSON.parse(readFileSync(conf,'utf8')).mcpServers.remote;
  assert.equal(active.args[1],'bridge');
  assert.ok(!JSON.stringify(active).includes('DEV_SECRET_DO_NOT_PERSIST'));
  assert.equal(statSync(result.backup).mode & 0o777,0o600);
  assert.throws(()=>installProxy(opts),/Already installed/);
  uninstallProxy({configFile:conf,server:'remote'});
  assert.deepEqual(JSON.parse(readFileSync(conf,'utf8')),data);
});

test('HTTPS requirement blocks accidental unencrypted remote credentials',t=>{
  const {config:conf}=workspace(t);
  writeFileSync(conf,JSON.stringify(config('http://api.external.example/mcp')));
  assert.throws(()=>configuredHttpServer(conf,'remote'),/HTTPS remote/);
  writeFileSync(conf,JSON.stringify(config('https://user:pass@api.example/mcp')));
  assert.throws(()=>configuredHttpServer(conf,'remote'),/credentials/);
});

test('redirects never forward authorization headers to a second host',async t=>{
  const {db,config:conf}=workspace(t),fx=await fixture(t,{redirect:true});
  writeFileSync(conf,JSON.stringify(config(fx.url)));
  const lines=[],bridge=new HttpBridge({server:configuredHttpServer(conf,'remote'),db,emit:s=>lines.push(s)});
  await bridge.accept(JSON.stringify(init));await bridge.close();
  assert.equal(JSON.parse(lines[0]).error.code,-32000);
  assert.equal(fx.seen.length,1);
});

test('modern MCP Header Base64 sentinel used for non-ASCII tool names',async t=>{
  const {db,config:conf}=workspace(t),fx=await fixture(t);
  writeFileSync(conf,JSON.stringify(config(fx.url)));
  const bridge=new HttpBridge({server:configuredHttpServer(conf,'remote'),db,emit:()=>{}});
  await bridge.accept(JSON.stringify(rpc(3,'tools/call',{name:'área',arguments:{}})));
  await bridge.close();
  assert.equal(fx.seen[0].headers['mcp-name'],'=?base64?w6FyZWE=?=');
});
