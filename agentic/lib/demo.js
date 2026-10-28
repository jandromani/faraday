import { spawn } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { GraphStore } from './store.js';

/** Populate a local sample graph using the bundled synthetic MCP server. */
export async function runDemo(database, binPath) {
  const fixture = fileURLToPath(new URL('../tests/fixture_server.js', import.meta.url));
  const configPath=resolve(dirname(database),'demo-mcp-config.json');
  mkdirSync(dirname(configPath),{recursive:true,mode:0o700});
  writeFileSync(configPath,JSON.stringify({mcpServers:{demo:{command:process.execPath,args:[fixture]}}},null,2),{mode:0o600});
  const child=spawn(process.execPath,[binPath,'proxy','--config',configPath,'--server','demo','--db',database],
    {stdio:['pipe','pipe','pipe'],cwd:process.cwd()});
  const messages=[
    {jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-06-18',capabilities:{},clientInfo:{name:'demo',version:'1'}}},
    {jsonrpc:'2.0',method:'notifications/initialized'},
    {jsonrpc:'2.0',id:2,method:'tools/list'},
    {jsonrpc:'2.0',id:3,method:'tools/call',params:{name:'echo',arguments:{message:'hello'}}},
    {jsonrpc:'2.0',id:4,method:'tools/call',params:{name:'add',arguments:{a:1,b:2}}},
  ];
  await new Promise((resolve,reject)=>{
    let count=0,carry='',done=false;
    const timeout=setTimeout(()=>{child.kill();reject(new Error('MCP demo timeout'));},8000);
    child.stdout.on('data',chunk=>{
      carry+=chunk.toString('utf8');let index;
      while((index=carry.indexOf('\n'))!==-1){const line=carry.slice(0,index);carry=carry.slice(index+1);
        if(line.trim())try{JSON.parse(line);count++;}catch{}
      }
      if(!done&&count>=4){done=true;clearTimeout(timeout);child.stdin.end();}
    });
    child.once('error',e=>{clearTimeout(timeout);reject(e);});
    child.once('close',code=>{clearTimeout(timeout);if(code===0&&count===4)resolve();else reject(new Error('MCP demo failed'));});
    for(const msg of messages)child.stdin.write(JSON.stringify(msg)+'\n');
  });
  const store=new GraphStore(database);
  try{return store.snapshot().stats;}finally{store.close();}
}
