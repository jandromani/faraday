import { safeLabel } from './discover.js';
import { denialReply } from './security-policy.js';

const MAX_OBSERVED_LINE = 1024 * 1024;
const tracked = new Set([
  'initialize','ping','tools/list','tools/call','resources/list','resources/read',
  'prompts/list','prompts/get','completion/complete','logging/setLevel',
  'notifications/initialized','notifications/tools/list_changed',
  'notifications/resources/list_changed','notifications/cancelled'
]);
const op = (raw) => tracked.has(raw) ? raw : 'other';
const keyFor = (id) => `${typeof id}:${JSON.stringify(id)}`;

/** Passive observer: collects only safe metadata; never mutates JSON-RPC frames. */
export class McpObserver {
  constructor(store, server) {
    this.store = store;
    this.server = safeLabel(server);
    this.inflight = { client: new Map(), server: new Map() };
    this.partialTools = null;
    this.listEpoch = 0;
    this.store.observedServer(this.server);
  }
  consume(raw, direction) {
    if (Buffer.byteLength(raw) > MAX_OBSERVED_LINE) return;
    let message;
    try { message = JSON.parse(raw); } catch { return; }
    const batch = Array.isArray(message) ? message.slice(0, 100) : [message];
    for (const m of batch) {
      if (m && typeof m === 'object' && !Array.isArray(m)) {
        try { this.message(m, direction); } catch { /* Observability must not interrupt MCP traffic. */ }
      }
    }
  }
  message(m, direction) {
    const sender = direction === 'client_to_server' ? 'client' : 'server';
    if (typeof m.method === 'string') {
      const method = op(m.method);
      const isRequest = Object.hasOwn(m,'id');
      const name = m.method === 'tools/call' && typeof m.params?.name === 'string' ? safeLabel(m.params.name) : null;
      if (isRequest) {
        const pending = this.inflight[sender];
        if (pending.size >= 2048) pending.clear();
        const cursor=m.params?.cursor;
        if(m.method==='tools/list' && cursor===undefined){this.partialTools=null;this.listEpoch++;}
        pending.set(keyFor(m.id), { method, name, started: performance.now(),
          listCursor:cursor,listEpoch:this.listEpoch });
        this.store.event({server:this.server,direction:'request',kind: name ? 'tool_call' : 'rpc', operation:method, tool:name});
        if (name) this.store.tool(this.server, name, 'called');
      } else {
        this.store.event({server:this.server,direction:'notification',kind:'rpc',operation:method});
      }
      return;
    }
    if (!Object.hasOwn(m, 'id')) return;
    const pending = this.inflight[sender === 'server' ? 'client' : 'server'];
    const state = pending.get(keyFor(m.id));
    if (!state) return;
    pending.delete(keyFor(m.id));
    const outcome = m.error || m.result?.isError === true ? 'error' : 'ok';
    this.store.event({server:this.server,direction:'response',kind:state.name ? 'tool_call' : 'rpc',
      operation:state.method,tool:state.name,status:outcome,
      latencyMs:Math.round(performance.now() - state.started)});
    if(state.method==='tools/list' && state.listEpoch===this.listEpoch && (outcome!=='ok'||!Array.isArray(m.result?.tools))){this.partialTools=null;return;}
    if (state.method === 'tools/list' && Array.isArray(m.result?.tools)) {
      const page=m.result.tools.slice(0, 1000);
      // Do not treat a partial, errored or truncated tools/list page as a full
      // contract manifest; that could produce false reports of removed tools.
        if(state.listEpoch!==this.listEpoch)return;
        if (outcome!=='ok' || m.result.tools.length>1000 ||
          (m.result.nextCursor!==undefined && (typeof m.result.nextCursor!=='string'||!m.result.nextCursor||m.result.nextCursor.length>4096))) {this.partialTools=null;return;}
        if(state.listCursor===undefined) this.partialTools={tools:[],nextCursor:null};
        else if(typeof state.listCursor!=='string'||!this.partialTools||state.listCursor!==this.partialTools.nextCursor){this.partialTools=null;return;}
        this.partialTools.tools.push(...page);
        if(this.partialTools.tools.length>2000){this.partialTools=null;return;}
        if(m.result.nextCursor!==undefined){this.partialTools.nextCursor=m.result.nextCursor;return;}
        const complete=this.partialTools.tools;this.partialTools=null;
      this.store.replaceContracts(this.server,complete);
    }
  }
}

/** Tee byte-for-byte streams; observe complete newline records up to a cap. */
export function tapJsonLines(source, destination, observer, direction) {
  let carry = Buffer.alloc(0);
  let oversized = false;
  source.on('data', (chunk) => {
    // Forward EXACT input bytes first, even if the message is invalid or oversized.
    if (!destination.write(chunk)) source.pause();
    let start = 0;
    for (let i=0; i<chunk.length; i++) {
      if (chunk[i] !== 10) continue;
      const part = chunk.subarray(start, i);
      if (!oversized && carry.length + part.length <= MAX_OBSERVED_LINE) {
        const raw = Buffer.concat([carry,part]).toString('utf8').trim();
        if (raw) observer.consume(raw,direction);
      }
      carry = Buffer.alloc(0);
      oversized = false;
      start = i+1;
    }
    const tail = chunk.subarray(start);
    if (!oversized && carry.length + tail.length <= MAX_OBSERVED_LINE)
      carry = Buffer.concat([carry, tail]);
    else { carry = Buffer.alloc(0); oversized = true; }
  });
  destination.on('drain', () => source.resume());
  source.on('end', () => destination.end());
}


/** Explicit local policy in stdio transport: block unapproved tool calls. */
export function tapGuardedJsonLines(source,destination,observer,policy,replySink){
  const MAX=2*1024*1024;
  let carry=Buffer.alloc(0),broken=false;
  source.on('data',chunk=>{
    if(broken)return;
    carry=Buffer.concat([carry,chunk]);
    if(carry.length>MAX){
      broken=true;source.pause();destination.end();
      process.stderr.write('[FARADAY] Oversized MCP frame blocked\n');return;
    }
    let idx;
    while((idx=carry.indexOf(10))>=0){
      const line=carry.subarray(0,idx).toString('utf8').replace(/\r$/,'');
      const frame=carry.subarray(0,idx+1);
      carry=carry.subarray(idx+1);
      if(!line.trim())continue;
      let obj;
      try{obj=JSON.parse(line);}catch{
        broken=true;source.pause();destination.end();
        process.stderr.write('[FARADAY] Invalid JSON-RPC frame blocked\n');break;
      }
      const decision=policy.decision(obj);
      observer.consume(line,'client_to_server');
      if(!decision.allowed){
        const msg=denialReply(obj);
        if(msg){observer.consume(msg.trim(),'server_to_client');replySink.write(msg);}
      } else if(!destination.write(frame))source.pause();
    }
  });
  destination.on('drain',()=>source.resume());
  source.on('end',()=>{if(carry.length)process.stderr.write('[FARADAY] Partial MCP frame discarded\n');destination.end();});
}
