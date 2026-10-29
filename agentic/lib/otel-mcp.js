/** Privacy-first OpenTelemetry-compatible MCP span envelope. No exporter, no content. */
import {randomBytes,createHash} from 'node:crypto';
const METHODS=new Set(['tools/call','tools/list','initialize','server/discover','prompts/get','resources/read']);
const hash=s=>createHash('sha256').update(s).digest('hex').slice(0,16);
const safe=(s,n)=>typeof s==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(s)&&!/^0+$/.test(s);
export function toSafeOtelMcpSpan({method,tool,decision,durationMs=0,traceId,spanId}={}){
 if(!METHODS.has(method))throw Error('unsupported MCP method');
 if(!['allow','deny','error'].includes(decision))throw Error('invalid span decision');
 if(typeof durationMs!=='number'||!Number.isFinite(durationMs)||durationMs<0||durationMs>3600000)throw Error('invalid span duration');
 if(tool!==undefined&&(typeof tool!=='string'||tool.length>256||tool.length===0))throw Error('invalid tool');
 if(method!=='tools/call'&&tool!==undefined)throw Error('tool only for execution');
 const t=traceId??randomBytes(16).toString('hex'),s=spanId??randomBytes(8).toString('hex');
 if(!safe(t,32)||!safe(s,16))throw Error('invalid trace IDs');
 const attributes={'mcp.method.name':method,'faraday.policy.decision':decision};
 if(method==='tools/call'){attributes['gen_ai.operation.name']='execute_tool';if(tool)attributes['faraday.tool.fingerprint']=hash(tool);}
 return Object.freeze({traceId:t,spanId:s,name:method==='tools/call'?'tools/call':'mcp.'+method,kind:'SPAN_KIND_SERVER',durationMs,attributes,status:{code:decision==='error'?'STATUS_CODE_ERROR':'STATUS_CODE_UNSET'},privacy:'metadata-only',semanticConventionStatus:'development'});
}
