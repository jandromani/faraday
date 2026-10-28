/** FARADAY Lab 0.8 — offline deterministic evaluation (not a penetration test).
 * Dummy actors are synthetic and never connect to real services.
 * Unsupported security capabilities are classified as gaps, not passes.
 */
import {ToolPolicy} from './security-policy.js';
import {validatedMcpUrl} from './egress-guard.js';
import {compareSnapshots, normalizeSchema, digest} from './contracts.js';
import {createHash} from 'node:crypto';
export const DUMMY_AGENTS=Object.freeze([
 ['explorer','read-only document explorer'],['support','synthetic support tickets'],
 ['developer','sandbox code maintenance'],['deployer','fake release management'],
 ['finance','simulated invoices'],['researcher','untrusted web and RAG'],
 ['orchestrator','agent delegation'],['browser','synthetic browser automation'],
 ['adversary','adversarial intents'],['rogue-mcp','malicious MCP fixture'],
 ['memory-poisoner','untrusted knowledge fixture'],['chaos','failure injection'],
].map(([id,role])=>Object.freeze({id,role,kind:'synthetic',canReachProduction:false})));
export const DISTRIBUTION=Object.freeze({legitimate:250,authorization:200,prompt_injection:150,ssrf:100,identity:100,chaos:100,contracts:100});
const allow=new ToolPolicy({version:1,mode:'enforce',maxArgumentBytes:8192,
 allowedTools:{sandbox:['read_document','list_documents']}},'sandbox');
const rpc=(name)=>({jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:{id:'SYNTHETIC'}}});
function contract(required){
 const inputSchema=normalizeSchema({type:'object',properties:{id:{type:'string'},
  ...(required?{authorization_code:{type:'string'}}:{})},required:['id',...(required?['authorization_code']:[])]});
 return {format:'faraday-contract-snapshot',version:1,coverage:'synthetic-fixture',tools:[{
 server:'sandbox',tool:'read_document',inputSchema,outputSchema:null,fingerprint:digest(inputSchema),
 potentialClients:['synthetic-explorer']}]};
}
export function generateScenarios(seed=42){
 if(!Number.isSafeInteger(seed)||seed<0||seed>0xffffffff)throw Error('Invalid lab seed');
 let state=seed>>>0;
 const rand=()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state;};
 const rows=[];
 for(const [category,count] of Object.entries(DISTRIBUTION))for(let i=0;i<count;i++){
  const agent=DUMMY_AGENTS[rand()%DUMMY_AGENTS.length].id;
  rows.push({id:category+'-'+String(i+1).padStart(4,'0'),category,agent,variant:rand()%10000,
   expected:category==='legitimate'?'allow':(['authorization','ssrf','contracts'].includes(category)?'deny':'unimplemented')});
 }
 return rows;
}
function execute(s){
 if(s.category==='legitimate')return {actual:allow.decision(rpc(s.variant%2?'read_document':'list_documents')).allowed?'allow':'deny',verified:true};
 if(s.category==='authorization')return {actual:allow.decision(rpc('delete_everything')).allowed?'allow':'deny',verified:true};
 if(s.category==='ssrf'){
  const urls=['https://169.254.169.254/latest/meta-data','http://10.1.2.3/mcp','https://127.0.0.2/mcp','http://metadata.google.internal/mcp'];
  try{validatedMcpUrl(urls[s.variant%urls.length]);return {actual:'allow',verified:true};}
  catch{return {actual:'deny',verified:true};}
 }
 if(s.category==='contracts')return {actual:compareSnapshots(contract(false),contract(true)).summary.breaking>0?'deny':'allow',verified:true};
 const reasons={prompt_injection:'Semantic prompt-injection enforcement unavailable',
  identity:'Authenticated workload identity unavailable',chaos:'Isolated execution and idempotent recovery unavailable'};
 return {actual:'unimplemented',verified:false,reason:reasons[s.category]};
}
export function runLab({seed=42,limit=1000,includeCases=false}={}){
 if(!Number.isSafeInteger(limit)||limit<1||limit>1000)throw Error('Lab limit must be 1..1000');
 const results=generateScenarios(seed).slice(0,limit).map(s=>{
  const r=execute(s),status=!r.verified?'gap':r.actual===s.expected?'pass':'fail';return {...s,...r,status};
 });
 const summary={total:results.length,passed:0,failed:0,gaps:0},categories={};
 for(const r of results){
  const key=r.status==='pass'?'passed':r.status==='fail'?'failed':'gaps';
  summary[key]++;const c=categories[r.category]??={total:0,passed:0,failed:0,gaps:0};c.total++;c[key]++;
 }
 const sha256=createHash('sha256').update(JSON.stringify({seed,categories,summary})).digest('hex');
 return {format:'faraday-lab-evaluation',version:1,release:'0.8.0',mode:'offline-synthetic',
  seed,agents:DUMMY_AGENTS.length,summary,categories,sha256,
  findings:results.filter(x=>x.status!=='pass').slice(0,12).map(x=>({id:x.id,status:x.status,reason:x.reason||'Unexpected result'})),
  ...(includeCases?{cases:results}:{}),
  limitations:['Synthetic rule-oracle tests only; no live AI agents or production tools.',
   'SSRF tests check URL rejection only, not end-to-end network isolation.',
   'Gaps are explicitly unsupported controls and do not count as successful evaluations.']};
}
export function labConfig({serverScript,nodePath=process.execPath}={}){
 if(!serverScript||typeof serverScript!=='string')throw Error('Lab server script required');
 return {mcpServers:{'faraday-synthetic-lab':{command:nodePath,args:[serverScript]}}};
}
