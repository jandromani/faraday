/** TrustDiff: tool allowlist diff only, never proof of real resource reachability. */
import {lstatSync,readFileSync} from 'node:fs';
import {safeLabel} from './discover.js';
import {ToolPolicy} from './security-policy.js';
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
function edges(p){
 if(!obj(p)||p.version!==1||p.mode!=='enforce'||!obj(p.allowedTools)||
   Object.keys(p).some(key=>!['version','mode','allowedTools','allowedMethods','maxArgumentBytes'].includes(key)))throw Error('Invalid FARADAY policy');
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
function methods(policy){
 if(!Object.hasOwn(policy,'allowedMethods'))return null;
 if(!Array.isArray(policy.allowedMethods)||policy.allowedMethods.length>1000||
    policy.allowedMethods.some(method=>typeof method!=='string'||!method||method.length>200))throw Error('Invalid method allowlist');
 return new Set(policy.allowedMethods);
}
export function diffAuthority(before,after){
 const prev=new Set(edges(before)),next=new Set(edges(after));
 const previousMethods=methods(before),nextMethods=methods(after);
 const methodsAdded=previousMethods&&nextMethods?[...nextMethods].filter(method=>!previousMethods.has(method)):[];
 const methodsRemoved=previousMethods&&nextMethods?[...previousMethods].filter(method=>!nextMethods.has(method)):[];
 const unrestrictedMethods=previousMethods!==null&&nextMethods===null;
 const methodsExpanded=unrestrictedMethods||methodsAdded.length>0;
 const added=[...next].filter(x=>!prev.has(x)).map(x=>JSON.parse(x)).map(([server,tool])=>({server:safeLabel(server),tool:safeLabel(tool)}));
 const removed=[...prev].filter(x=>!next.has(x)).map(x=>JSON.parse(x)).map(([server,tool])=>({server:safeLabel(server),tool:safeLabel(tool)}));
 const a=before.maxArgumentBytes??8192,b=after.maxArgumentBytes??8192;
 if(!Number.isSafeInteger(a)||!Number.isSafeInteger(b)||a<32||b<32||a>131072||b>131072)throw Error('Invalid maxArgumentBytes');
 return {format:'faraday-trust-diff',version:1,summary:{
  before:prev.size,after:next.size,added:added.length,removed:removed.length,
   authorityExpanded:added.length>0||b>a||methodsExpanded},
  added,removed,maxArgumentBytes:{before:a,after:b,expanded:b>a},
   methods:{before:previousMethods===null?'unrestricted':'allowlist',after:nextMethods===null?'unrestricted':'allowlist',
    added:methodsAdded.map(safeLabel),removed:methodsRemoved.map(safeLabel),unrestrictedMethods,expanded:methodsExpanded},
   limitations:['Only configured tool and method names and argument byte limits are compared.',
   'No proof of resource authorization or network reachability.',
   'A permitted read tool could access sensitive resources.']};
}
export function simulateObservedDecisions(before,after,observations){
 diffAuthority(before,after);
 if(!Array.isArray(observations)||observations.length>256)throw Error('Invalid observed decisions');
 let bytes;try{bytes=Buffer.byteLength(JSON.stringify(observations));}catch{throw Error('Invalid observed decisions');}
 if(bytes>512*1024)throw Error('Observed decisions too large');
 const decision=(policy,entry)=>Object.hasOwn(policy.allowedTools,entry.server)?
  (new ToolPolicy(policy,entry.server).decision(entry.message).allowed?'allow':'deny'):'configuration-error';
 const results=observations.map((entry,index)=>{
  if(!obj(entry)||Object.keys(entry).length!==3||!['server','message','observedAllowed'].every(key=>Object.hasOwn(entry,key))||
     typeof entry.server!=='string'||!entry.server||entry.server.length>128||!obj(entry.message)||typeof entry.observedAllowed!=='boolean')throw Error('Invalid observed decision');
  const baseline=decision(before,entry),proposed=decision(after,entry);
  return {index,observed:entry.observedAllowed?'allow':'deny',baseline,proposed,
   baselineMatches:baseline==='configuration-error'?null:(baseline==='allow')===entry.observedAllowed};
 });
 return {format:'faraday-observed-decision-preflight',version:1,mode:'offline-no-effects',results,
  summary:{observations:results.length,baselineMismatches:results.filter(x=>x.baselineMatches===false).length,
   baselineUnavailable:results.filter(x=>x.baselineMatches===null).length,proposedUnavailable:results.filter(x=>x.proposed==='configuration-error').length,
   changed:results.filter(x=>x.baseline!==x.proposed).length},
  limitations:['Observations are caller-supplied and not authenticated.',
   'Only ToolPolicy decisions are compared; no tools, resources or effects are executed or verified.']};
}
export function readPolicy(path){
 const source=readFileSync(path,'utf8');
 if(Buffer.byteLength(source)>128*1024)throw Error('Policy too large');
 return JSON.parse(source);
}
export function readObservedDecisions(path){
 const stat=lstatSync(path);if(!stat.isFile()||stat.isSymbolicLink()||stat.size>512*1024)throw Error('Unsafe observed decisions file');
 return JSON.parse(readFileSync(path,'utf8'));
}
export function affectedClients(graph,server){
 const id='server:'+safeLabel(server);
 const clients=new Set(graph.edges.filter(e=>e.dst===id&&e.relation==='configured').map(e=>e.src));
 return graph.nodes.filter(n=>clients.has(n.id)&&n.type==='client').map(n=>n.label).sort();
}
