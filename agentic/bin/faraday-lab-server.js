#!/usr/bin/env node
/** Synthetic stdio MCP fixture; no outbound calls, real payments, or code execution. */
import {createInterface} from 'node:readline';
import {DUMMY_AGENTS} from '../lib/lab.js';
const actors=new Map(DUMMY_AGENTS.map(a=>['simulate_'+a.id,a]));
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
function answer(msg){
 if(!obj(msg)||msg.jsonrpc!=='2.0'||typeof msg.method!=='string'||!Object.hasOwn(msg,'id'))return null;
 if(typeof msg.id!=='number'&&typeof msg.id!=='string')return null;
 const ok=result=>({jsonrpc:'2.0',id:msg.id,result});
 const err=message=>({jsonrpc:'2.0',id:msg.id,error:{code:-32602,message}});
 if(msg.method==='initialize')return ok({protocolVersion:'2025-11-25',
  capabilities:{tools:{}},serverInfo:{name:'faraday-synthetic-lab',version:'0.8.0'}});
 if(msg.method==='server/discover')return ok({serverInfo:{name:'faraday-synthetic-lab',version:'0.8.0'},capabilities:{tools:{}}});
 if(msg.method==='tools/list')return ok({tools:DUMMY_AGENTS.map(a=>({
  name:'simulate_'+a.id,description:'Synthetic fixture only, with no external side effects',
  inputSchema:{type:'object',properties:{action:{type:'string'},resource:{type:'string'}},required:['action']}
 }))});
 if(msg.method==='tools/call'){
  const actor=actors.get(msg.params?.name),args=msg.params?.arguments;
  if(!actor)return err('Unknown synthetic tool');
  if(!obj(args)||typeof args.action!=='string'||args.action.length>100||
     (args.resource!==undefined&&(typeof args.resource!=='string'||args.resource.length>100)))return err('Invalid synthetic arguments');
  const allowed=['read','list','inspect'].includes(args.action);
  return ok({isError:!allowed,content:[{type:'text',text:JSON.stringify({
   actor:actor.id,decision:allowed?'SIMULATED_ALLOW':'SIMULATED_DENY',executedExternally:false})}]});
 }
 return {jsonrpc:'2.0',id:msg.id,error:{code:-32601,message:'Method not found'}};
}
for await(const line of createInterface({input:process.stdin,crlfDelay:Infinity})){
 if(Buffer.byteLength(line)>65536)continue;
 try{const response=answer(JSON.parse(line));if(response)process.stdout.write(JSON.stringify(response)+'\n');}catch{}
}
