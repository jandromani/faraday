/** Read-mostly MCP stdio interoperability probe. No tool calls unless user explicitly opts in.
 * Supports 2026-07-28 stateless discovery and legacy 2025-11-25 initialize.
 * Never captures tool descriptions, tool outputs, stderr or environment variables in reports.
 */
import {spawn} from 'node:child_process';
import {resolve} from 'node:path';
import {performance} from 'node:perf_hooks';
import {getExecutableServer} from './discover.js';

const MODERN='2026-07-28', LEGACY='2025-11-25', MAX_OUTPUT=2*1024*1024;
const META=Object.freeze({'io.modelcontextprotocol/protocolVersion':MODERN,
  'io.modelcontextprotocol/clientCapabilities':{},
  'io.modelcontextprotocol/clientInfo':{name:'faraday-live-probe',version:'0.99.2'}});
function ensureVersion(v){if(![MODERN,LEGACY].includes(v))throw Error('Unknown MCP probe protocol');}
function safeString(s){return typeof s==='string'&&s.length<=128&&/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(s)?s:'redacted';}
function validTimeout(ms){if(!Number.isInteger(ms)||ms<200||ms>60000)throw Error('timeoutMs must be 200..60000');}
function toolSummary(tools){return tools.map(x=>({name:safeString(x.name),readOnlyHint:x.annotations?.readOnlyHint===true}));}

export async function probeStdio({configFile,server,protocol='auto',timeoutMs=8000,
   maxPages=5,callTool=null,allowCall=false}={}) {
  if(!configFile||!server)throw Error('Provide --config and --server');
  if(!['auto','legacy','modern'].includes(protocol))throw Error('Protocol must be auto, legacy or modern');
  validTimeout(timeoutMs);
  if(!Number.isInteger(maxPages)||maxPages<1||maxPages>20)throw Error('maxPages must be 1..20');
  if(callTool&&!allowCall)throw Error('An explicit --allow-call is required to execute any MCP tool');
  if(callTool && safeString(callTool)!==callTool)throw Error('Invalid named tool');
  const cfg=getExecutableServer(resolve(configFile),server);
  const base=resolve(configFile,'..');
  const child=spawn(cfg.command,cfg.args,{cwd:cfg.cwd?resolve(base,cfg.cwd):base,
    env:{...process.env,...cfg.env},shell:false,windowsHide:true,stdio:['pipe','pipe','ignore']});
  child.stdin.on('error',()=>{});
  let buffer='', accumulated=0, nextId=1, aborted=false;
  const pending=new Map();
  const start=performance.now();
  const deadline=Date.now()+timeoutMs;
  const closeReason=()=>new Error('MCP server exited without completing probe');
  let exitHandler=()=>{};
  const closed=new Promise(resolveDone=>{exitHandler=resolveDone;});
  child.on('error',err=>{for(const p of pending.values())p.reject(new Error('Cannot spawn MCP server'));pending.clear();exitHandler(err);});
  child.on('exit',()=>{for(const p of pending.values())p.reject(closeReason());pending.clear();exitHandler();});
  child.stdout.on('data',chunk=>{
    accumulated+=chunk.length;
    if(accumulated>MAX_OUTPUT){aborted=true;child.kill();return;}
    buffer+=chunk.toString('utf8');
    if(buffer.length>MAX_OUTPUT){aborted=true;child.kill();return;}
    for(let pos;(pos=buffer.indexOf('\n'))!==-1;){
      const raw=buffer.slice(0,pos).trim();buffer=buffer.slice(pos+1);
      if(!raw)continue;
      let msg;try{msg=JSON.parse(raw);}catch{continue;}
      if(!msg||msg.jsonrpc!=='2.0'||typeof msg!=='object')continue;
      // Never respond to server-initiated sampling, roots or elicitation: probe is read-only.
      const p=pending.get(String(msg.id));
      if(!p)continue;
      pending.delete(String(msg.id));p.resolve(msg);
    }
  });
  const send=async(method,params={},notification=false)=>{
    if(aborted)throw Error('MCP response exceeded maximum size');
    const request={jsonrpc:'2.0',...(notification?{}:{id:nextId++}),method,params};
    if(notification){child.stdin.write(JSON.stringify(request)+'\n');return null;}
    if(Date.now()>=deadline)throw Error('MCP probe timed out');
    const id=String(request.id);
    let waitTimer;
    const response=await Promise.race([
      new Promise((ok,fail)=>{
        pending.set(id,{resolve:ok,reject:fail});
        child.stdin.write(JSON.stringify(request)+'\n',err=>{if(err){pending.delete(id);fail(Error('MCP transport unavailable'));}});
      }),
      new Promise((_,fail)=>{waitTimer=setTimeout(()=>fail(Error('MCP probe timed out')),Math.max(1,deadline-Date.now()));}),
    ]).finally(()=>{clearTimeout(waitTimer);pending.delete(id);});
    if(response.error)return {error:{code:response.error.code}};
    if(!response.result||typeof response.result!=='object')throw Error('Invalid MCP response');
    return {result:response.result};
  };
  try{
    let era,version,initial;
    if(protocol!=='legacy'){
      const response=await send('server/discover',{_meta:META});
      if(response.result && Array.isArray(response.result.supportedVersions) && response.result.supportedVersions.includes(MODERN)){
        era='modern';version=MODERN;initial=response.result;
      }else if(protocol==='modern')throw Error('Modern MCP protocol not supported');
      else if(response.error?.code===-32601||response.error?.code===-32022){era='legacy';}
      else throw Error('MCP discovery failed; use --protocol legacy for an older server');
    }else era='legacy';
    if(era==='legacy'){
      const response=await send('initialize',{protocolVersion:LEGACY,capabilities:{},clientInfo:{name:'faraday-live-probe',version:'0.99.2'}});
      if(!response.result||typeof response.result.protocolVersion!=='string')throw Error('Legacy MCP initialization failed');
      version=response.result.protocolVersion;
      if(!/^20\d{2}-\d{2}-\d{2}$/.test(version))throw Error('Invalid negotiated protocol version');
      initial=response.result;
      await send('notifications/initialized',{},true);
    }
    const used=new Set();let cursor, pages=0, total=0, tools=[],truncated=false;
    do {
      const params=era==='modern'?{...(cursor?{cursor}:{}),_meta:META}:cursor?{cursor}:{};
      const r=await send('tools/list',params);
      if(!r.result||!Array.isArray(r.result.tools))throw Error('MCP tools/list failed');
      pages++;total+=r.result.tools.length;
      if(total>1000)throw Error('MCP tool list exceeds probe cap');
      tools.push(...toolSummary(r.result.tools));
      cursor=r.result.nextCursor;
      if(cursor!=null && (typeof cursor!=='string'||cursor.length>512||used.has(cursor)))throw Error('Invalid or repeated cursor');
      if(cursor)used.add(cursor);
      if(cursor&&pages>=maxPages){truncated=true;break;}
    }while(cursor);
    const report={format:'faraday-mcp-live-probe',version:1,server:safeString(cfg.name),
      era,protocolVersion:version,toolsObserved:total,pages,truncated,
      elapsedMs:Math.round(performance.now()-start),
      result:'pass',invokedTools:false,toolNames:tools,scope:'stdio handshake + tools/list only; not MCP conformance or enforcement'};
    if(callTool){
      if(!tools.some(t=>t.name===callTool))throw Error('Requested MCP tool is not listed');
      const params={name:callTool,arguments:{},...(era==='modern'?{_meta:META}:{})};
      const response=await send('tools/call',params);
      report.invokedTools=true;
      report.toolCall={name:callTool,success:!!response.result&&!response.result.isError,errorCode:response.error?.code||null};
      // No tool output is copied into the report (including on failures).
      if(!report.toolCall.success)report.result='fail';
    }
    return report;
  }finally{
    for(const p of pending.values())p.reject(Error('Probe completed'));
    pending.clear();
    try{child.stdin.end();}catch{}
    child.kill();
    // Do not wait for stubborn external processes forever.
    await Promise.race([closed,new Promise(r=>setTimeout(r,150))]);
  }
}
