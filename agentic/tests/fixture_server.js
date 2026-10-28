import { createInterface } from 'node:readline';
// A deliberately fake stdio MCP server; it executes nothing outside this process.
const rl=createInterface({input:process.stdin,crlfDelay:Infinity});
function handle(msg) {
  if (Array.isArray(msg)) {msg.forEach(handle);return;}
  if (msg.id===undefined || !msg.method) return;
  let result;
  if(msg.method==='initialize') result={protocolVersion:'2025-06-18',capabilities:{tools:{listChanged:true}},serverInfo:{name:'faraday-test',version:'0.0.1'}};
  else if(msg.method==='tools/list') result={tools:[{name:'echo',description:'echo',inputSchema:{type:'object',properties:{message:{type:'string'}}}},{name:'add',inputSchema:{type:'object'}}]};
  else if(msg.method==='tools/call') result={content:[{type:'text',text:'SECRET_DO_NOT_LOG:'+JSON.stringify(msg.params?.arguments)}],isError:msg.params?.name==='error'};
  else result={};
  process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:msg.id,result})+'\n');
}
rl.on('line',(line)=>{try{handle(JSON.parse(line));}catch{}});
