/** FARADAY Build 005: stdio-client to configured Streamable HTTP server bridge.
 * No arbitrary target URLs. No logs of HTTP bodies, credentials, arguments, or results.
 * This is an observability adapter, NOT a security enforcement boundary.
 */
import { createInterface } from 'node:readline';
import { GraphStore } from './store.js';
import { McpObserver } from './observe.js';
import { configServers, readMcpConfig, safeLabel } from './discover.js';
import { resolve } from 'node:path';
import { validatedMcpUrl, secureMcpFetch } from './egress-guard.js';
import { denialReply,loadToolPolicy } from './security-policy.js';

const MAX_FRAME = 2 * 1024 * 1024;
const MAX_SSE_EVENT = MAX_FRAME;
const CLIENT_HEADER_DENY = new Set([
  'host','connection','content-length','content-type','accept','transfer-encoding',
  'mcp-protocol-version','mcp-method','mcp-name','mcp-session-id','last-event-id',
  'origin','forwarded','x-forwarded-for','x-forwarded-host','x-forwarded-proto',
]);

function requiredUrl(text) { return validatedMcpUrl(text).href; }

export function configuredHttpServer(configPath, name) {
  if (!configPath || !name) throw Error('HTTP bridge needs --config and --server');
  const matched = configServers(readMcpConfig(resolve(configPath))).filter(x => x.name === name);
  if (matched.length !== 1 || matched[0].transport !== 'http') throw Error('Named HTTP MCP server not found');
  const data = matched[0].data;
  if (data.type && !['http','streamable-http'].includes(data.type)) throw Error('Legacy SSE server transport is unsupported');
  if (data.headers != null && (typeof data.headers !== 'object' || Array.isArray(data.headers))) throw Error('Invalid server headers');
  const headers = {};
  for (const [name,value] of Object.entries(data.headers || {})) {
    const lower = name.toLowerCase();
    if (!/^[a-z0-9-]+$/.test(lower) || CLIENT_HEADER_DENY.has(lower)) throw Error('Reserved MCP header in server configuration');
    if (typeof value !== 'string' || value.length > 8192) throw Error('Invalid configured header');
    const resolved = value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_,n) => {
      if (!Object.hasOwn(process.env,n)) throw Error('Missing environment variable in MCP header');
      return process.env[n];
    });
    if (/[\r\n]/.test(resolved)) throw Error('Forbidden header newline');
    headers[lower] = resolved;
  }
  return { name:safeLabel(name), url:requiredUrl(data.url), headers };
}

const isObj = o => !!o && typeof o === 'object' && !Array.isArray(o);
function encodeHeaderValue(value) {
  const s=String(value);
  if (/^[\x20-\x7e]*$/.test(s) && s.trim()===s && !(/^=\?base64\?.*\?=$/.test(s))) return s;
  return '=?base64?' + Buffer.from(s,'utf8').toString('base64') + '?=';
}
function schemaMirrorPaths(schema, path=[], depth=0, out=[]) {
  if (!isObj(schema) || depth>8 || out.length>32) return out;
  if (typeof schema['x-mcp-header']==='string' && path.length &&
      /^[A-Za-z0-9-]{1,64}$/.test(schema['x-mcp-header']) &&
      ['string','integer','boolean'].includes(schema.type)) {
    out.push({name:'mcp-param-'+schema['x-mcp-header'], path});
  }
  if (isObj(schema.properties)) for (const [k,v] of Object.entries(schema.properties).slice(0,100))
    schemaMirrorPaths(v,[...path,k],depth+1,out);
  return out;
}
function resolvedValue(args,path) {
  let value=args;
  for (const p of path) { if (!isObj(value) || !Object.hasOwn(value,p)) return undefined;value=value[p]; }
  return value;
}

function validateMessage(json) {
  if (!isObj(json) || json.jsonrpc !== '2.0' || Array.isArray(json.params)) throw Error('Expected one JSON-RPC object');
  if (typeof json.method !== 'string' && !Object.hasOwn(json,'id')) throw Error('Not a JSON-RPC message');
}
function methodHeaders(message, headersByTool) {
  const hdr = {};
  const version = message.params?._meta?.['io.modelcontextprotocol/protocolVersion'] ||
    (message.method === 'initialize' ? message.params?.protocolVersion : null);
  if (typeof version === 'string' && /^20\d{2}-\d{2}-\d{2}$/.test(version)) hdr['mcp-protocol-version'] = version;
  if (typeof message.method === 'string') {
    hdr['mcp-method'] = message.method;
    if (['tools/call','prompts/get','resources/read'].includes(message.method)) {
      const name = message.method === 'resources/read' ? message.params?.uri : message.params?.name;
      if (typeof name === 'string' && name) {
        // Header values are untrusted; avoid injecting non-ASCII or CRLF.
        hdr['mcp-name'] = encodeHeaderValue(name);
      }
    }
  }
  if(message.method==='tools/call' && typeof message.params?.name==='string') {
    const defs=headersByTool.get(message.params.name)||[];
    for(const def of defs) {
      const v=resolvedValue(message.params?.arguments,def.path);
      if(v===undefined || v===null) continue;
      if(!['string','number','boolean'].includes(typeof v)) continue;
      if(typeof v==='number' && (!Number.isSafeInteger(v))) continue;
      hdr[def.name]=encodeHeaderValue(v);
    }
  }
  return hdr;
}

async function* sseData(body) {
  if (!body) throw Error('Missing SSE response body');
  const decoder = new TextDecoder();
  let buffer = '', data = [], size = 0;
  for await (const chunk of body) {
    buffer += decoder.decode(chunk,{stream:true});
    if (buffer.length > MAX_SSE_EVENT * 2) throw Error('SSE buffer too large');
    let idx;
    while ((idx=buffer.indexOf('\n'))!==-1) {
      const line = buffer.slice(0,idx).replace(/\r$/,'');
      buffer = buffer.slice(idx+1);
      if (line === '') {
        if (data.length && data.join('\n')!=='') yield data.join('\n');
        data=[];size=0;
      } else if (line.startsWith('data:')) {
        const next=line.slice(5).replace(/^ /,'');
        size+=next.length;
        if (size > MAX_SSE_EVENT) throw Error('SSE event too large');
        data.push(next);
      }
    }
  }
  if (buffer.trim()) throw Error('Incomplete SSE stream');
}

/** Relay configured outbound MCP calls into stdin/stdout JSON-RPC streams. */
export class HttpBridge {
  constructor({server, db, emit, fetcher=secureMcpFetch, timeoutMs=60000, policy=null}) {
    if (!server || typeof server.url !== 'string') throw Error('Invalid HTTP MCP configuration');
    this.server = server;
    this.store = new GraphStore(db);
    this.observer = new McpObserver(this.store,server.name);
    this.emit = emit;
    this.fetcher = fetcher;
    this.timeoutMs = timeoutMs;
    this.policy = policy;
    this.sessionId = null;
    this.protocolVersion = null;
    this.pending = new Set();
    this.toolHeaderDefs = new Map();
    this.initialization = Promise.resolve();
    this.closed=false;
  }
  async accept(raw) {
    if (Buffer.byteLength(raw) > MAX_FRAME) return;
    let message;
    try { message=JSON.parse(raw);validateMessage(message); }
    catch { return; }
    this.observer.consume(raw,'client_to_server');
    if(this.policy && !this.policy.decision(message).allowed){
      const denied=denialReply(message);
      if(denied){this.observer.consume(denied.trim(),'server_to_client');this.emit(denied);}
      return;
    }
    if(this.pending.size>=64){this._error(message);return;}
    if (message.method === 'initialize') {
      const p=this._send(message);
      this.initialization=p.catch(()=>{});
      return this._track(p);
    }
    const p=this.initialization.then(()=>this._send(message));
    return this._track(p);
  }
  _track(p) { this.pending.add(p);p.finally(()=>this.pending.delete(p)).catch(()=>{});return p; }
  _emitRPC(raw,request,{answered=false,requireResponse=false}={}) {
    if (Buffer.byteLength(raw)>MAX_FRAME) throw Error('HTTP message too large');
    const obj=JSON.parse(raw);validateMessage(obj);
    const response=typeof obj.method!=='string'&&Object.hasOwn(obj,'id')&&
      (Object.hasOwn(obj,'result')||Object.hasOwn(obj,'error'));
    if(typeof request.method==='string'&&Object.hasOwn(request,'id')&&
       ((response&&(obj.id!==request.id||answered))||(requireResponse&&!response)))throw Error('Mismatched HTTP response');
    if(request.method==='initialize' && obj.id===request.id && !obj.error &&
       typeof obj.result?.protocolVersion==='string' && /^20\d{2}-\d{2}-\d{2}$/.test(obj.result.protocolVersion))
      this.protocolVersion=obj.result.protocolVersion;
    if(Array.isArray(obj.result?.tools)) for(const tool of obj.result.tools.slice(0,1000)) {
      if (typeof tool?.name==='string') this.toolHeaderDefs.set(tool.name,schemaMirrorPaths(tool.inputSchema));
    }
    this.observer.consume(raw,'server_to_client');
    this.emit(raw+'\n');
    return obj;
  }
  _error(message) {
    if (typeof message.method==='string' && Object.hasOwn(message,'id')) {
      const reply=JSON.stringify({jsonrpc:'2.0',id:message.id,error:{code:-32000,message:'FARADAY HTTP bridge upstream unavailable'}});
      this.observer.consume(reply,'server_to_client');
      this.emit(reply+'\n');
    }
  }
  async _send(message) {
    if (this.closed) return;
    const abort=new AbortController();
    const timeout=setTimeout(()=>abort.abort(),this.timeoutMs);
    let answered=false;
    try {
      const headers={...this.server.headers,'content-type':'application/json',
        'accept':'application/json, text/event-stream',...methodHeaders(message,this.toolHeaderDefs)};
      if (this.protocolVersion && message.method!=='initialize') headers['mcp-protocol-version']=this.protocolVersion;
      if (this.sessionId) headers['mcp-session-id']=this.sessionId;
      const response=await this.fetcher(this.server.url,{
        method:'POST',headers,body:JSON.stringify(message),redirect:'manual',signal:abort.signal,
      });
      // No redirect following: prevents secret exfiltration through redirects.
      if (response.status>=300 && response.status<400){if(response.discard)await response.discard();throw Error('Upstream redirect rejected');}
      const session=response.headers.get('mcp-session-id');
      if (session && /^[\x21-\x7e]{1,256}$/.test(session)) this.sessionId=session;
      if (response.status===202 && (!Object.hasOwn(message,'id')||typeof message.method!=='string')) return;
      const contentType=(response.headers.get('content-type')||'').toLowerCase();
      if (!response.ok){
        if(Object.hasOwn(message,'id')&&typeof message.method==='string'&&contentType.includes('application/json')){
          const raw=await response.text();
          if(Buffer.byteLength(raw)>MAX_FRAME)throw Error('HTTP message too large');
          const error=JSON.parse(raw);
          if(isObj(error)&&error.jsonrpc==='2.0'&&isObj(error.error)&&Number.isSafeInteger(error.error.code)&&
             typeof error.error.message==='string'&&(error.id==null||error.id===message.id)){
            this._emitRPC(JSON.stringify({...error,id:message.id}),message,{requireResponse:true});return;
          }
        }else if(response.discard)await response.discard();
        throw Error('Upstream HTTP error');
      }
      if (contentType.includes('text/event-stream')) {
        for await (const frame of sseData(response.body)) {
          const item=this._emitRPC(frame,message,{answered});
          if(Object.hasOwn(message,'id')&&item.id===message.id&&typeof item.method!=='string'&&
             (Object.hasOwn(item,'result')||Object.hasOwn(item,'error')))answered=true;
        }
        if(Object.hasOwn(message,'id')&&!answered)throw Error('SSE stream ended without a response');
      } else if (contentType.includes('application/json')) {
        const raw=await response.text();
        this._emitRPC(raw,message,{requireResponse:true});
      } else throw Error('Unsupported upstream response type');
    } catch { if(!answered)this._error(message); }
    finally { clearTimeout(timeout); }
  }
  async close() {
    this.closed=true;
    await Promise.allSettled([...this.pending]);
    this.store.close();
  }
}

export async function bridgeMcp({configFile,server,database,policyFile}) {
  const config=configuredHttpServer(configFile,server);
  const policy=loadToolPolicy(policyFile,server);
  const bridge=new HttpBridge({server:config,db:database,policy,emit:raw=>process.stdout.write(raw)});
  const input=createInterface({input:process.stdin,crlfDelay:Infinity});
  const work=[];
  for await (const line of input) {
    if (!line.trim()) continue;
    work.push(bridge.accept(line).catch(()=>{}));
    if (work.length>10000) throw Error('Too many MCP frames');
  }
  await Promise.allSettled(work);
  await bridge.close();
}
