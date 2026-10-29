/** TrustDiff: tool allowlist diff only, never proof of real resource reachability. */
import {readFileSync} from 'node:fs';
import {safeLabel} from './discover.js';
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
function edges(p){
 if(!obj(p)||p.version!==1||p.mode!=='enforce'||!obj(p.allowedTools))throw Error('Invalid FARADAY policy');
 const results=[];
 for(const [server,tools] of Object.entries(p.allowedTools)){
  if(server.length>128||!Array.isArray(tools)||tools.length>1000)throw Error('Invalid policy tools');
  for(const tool of tools){
   if(typeof tool!=='string'||tool.length>200||!tool)throw Error('Invalid tool');
   results.push(JSON.stringify([server,tool]));
  }
 }
 if(results.length>10000)throw Error('Too many policy entries');
 return [...new Set(results)].sort();
}
export function diffAuthority(before,after){
 const prev=new Set(edges(before)),next=new Set(edges(after));
 const added=[...next].filter(x=>!prev.has(x)).map(x=>JSON.parse(x)).map(([server,tool])=>({server:safeLabel(server),tool:safeLabel(tool)}));
 const removed=[...prev].filter(x=>!next.has(x)).map(x=>JSON.parse(x)).map(([server,tool])=>({server:safeLabel(server),tool:safeLabel(tool)}));
 const a=before.maxArgumentBytes??8192,b=after.maxArgumentBytes??8192;
 if(!Number.isSafeInteger(a)||!Number.isSafeInteger(b)||a<32||b<32)throw Error('Invalid maxArgumentBytes');
 return {format:'faraday-trust-diff',version:1,summary:{
  before:prev.size,after:next.size,added:added.length,removed:removed.length,
  authorityExpanded:added.length>0||b>a},
  added,removed,maxArgumentBytes:{before:a,after:b,expanded:b>a},
  limitations:['Only configured tool names and argument byte limits are compared.',
   'No proof of resource authorization or network reachability.',
   'A permitted read tool could access sensitive resources.']};
}
export function readPolicy(path){
 const source=readFileSync(path,'utf8');
 if(Buffer.byteLength(source)>128*1024)throw Error('Policy too large');
 return JSON.parse(source);
}
export function affectedClients(graph,server){
 const id='server:'+safeLabel(server);
 const clients=new Set(graph.edges.filter(e=>e.dst===id&&e.relation==='configured').map(e=>e.src));
 return graph.nodes.filter(n=>clients.has(n.id)&&n.type==='client').map(n=>n.label).sort();
}
