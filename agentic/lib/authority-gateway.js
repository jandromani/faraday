/** Preview gateway: pre-authorizes each synthetic action before forwarding to a fixed backend.
 * Not a generic OAuth2 / MCP authorization server. Production requires OIDC/SVID,
 * network policy, rate limiting, per-resource policy evolution and KMS key custody.
 */
import http from 'node:http';
import {AuthorityError} from './authority.js';
const MAX_REQUEST=32*1024;
export const GATEWAY_BACKEND_PATH='/internal/execute';
export async function readJson(req){
  if(req.headers['content-type']?.split(';')[0].trim()!=='application/json')throw new AuthorityError('invalid-content-type');
  const contentLength=Number(req.headers['content-length']);
  if(!Number.isSafeInteger(contentLength)||contentLength<1||contentLength>MAX_REQUEST)throw new AuthorityError('invalid-content-length');
  let size=0;const parts=[];
  for await(const chunk of req){size+=chunk.length;if(size>MAX_REQUEST)throw new AuthorityError('request-too-large');parts.push(chunk);}
  if(size!==contentLength)throw new AuthorityError('content-length-mismatch');
  let obj;try{obj=JSON.parse(Buffer.concat(parts).toString('utf8'));}catch{throw new AuthorityError('invalid-json');}
  if(!obj||typeof obj!=='object'||Array.isArray(obj))throw new AuthorityError('invalid-body');return obj;
}
const send=(res,code,data)=>{
  const blob=JSON.stringify(data);res.writeHead(code,{'content-type':'application/json','content-length':Buffer.byteLength(blob),'cache-control':'no-store','x-content-type-options':'nosniff'});res.end(blob);
};
export function createAuthorityGateway({gate,backendUrl,backendSecret,fetchFn=fetch,onDecision=()=>{}}){
  const endpoint=new URL(backendUrl);
  if(endpoint.pathname!==GATEWAY_BACKEND_PATH||endpoint.search||endpoint.hash||endpoint.username||endpoint.password||!['http:','https:'].includes(endpoint.protocol))throw Error('Fixed backend endpoint required');
  if(typeof backendSecret!=='string'||backendSecret.length<32)throw Error('Backend service secret of at least 32 bytes required');
  if(!gate||typeof gate.authorize!=='function')throw Error('Authority gate required');
  return http.createServer(async(req,res)=>{
    if(req.method==='GET'&&req.url==='/healthz')return send(res,200,{service:'faraday-authority-preview',status:'ok'});
    if(req.url!=='/execute'||req.method!=='POST')return send(res,404,{error:'not-found'});
    let authorized;
    try{
      const body=await readJson(req);
      if(Object.keys(body).sort().join('|')!=='capability|proof')throw new AuthorityError('invalid-request-schema');
      authorized=gate.authorize(body);
    }catch(e){
      try{onDecision({status:'denied',reason:e instanceof AuthorityError?e.code:'invalid-request'});}catch{}
      return send(res,e instanceof AuthorityError?403:400,{error:'denied'});
    }
    try{onDecision({status:'authorized',tool:authorized.tool,agent:authorized.agent});}
    catch{return send(res,503,{error:'audit-unavailable'});}
    // By design the caller cannot choose the host, path, headers or backend credentials.
    try{
      const upstream=await fetchFn(endpoint,{method:'POST',redirect:'error',signal:AbortSignal.timeout(3000),
        headers:{'content-type':'application/json','authorization':`Bearer ${backendSecret}`},
        body:JSON.stringify({tool:authorized.tool,resource:authorized.resource,action:authorized.action,
          args:authorized.args,operationId:authorized.jti})});
      if(!upstream.ok)return send(res,502,{error:'backend-rejected'});
      const bytes=Buffer.from(await upstream.arrayBuffer());
      if(bytes.length>MAX_REQUEST)return send(res,502,{error:'backend-response-oversized'});
      let result;try{result=JSON.parse(bytes.toString('utf8'));}catch{return send(res,502,{error:'backend-invalid-response'});}
      // Redact backend data in caller response. Synthetic fixture returns only action status.
      return send(res,200,{status:result.status==='simulated'?'simulated':'completed',operationId:authorized.jti,
        agent:authorized.agent,rule:authorized.rule});
    }catch{return send(res,503,{error:'backend-unavailable'});}
  });
}
export function createSyntheticBackend({secret}){
  if(typeof secret!=='string'||secret.length<32)throw Error('Backend service secret required');
  const committed=new Set();
  return http.createServer(async(req,res)=>{
    if(req.method==='GET'&&req.url==='/healthz')return send(res,200,{status:'ok'});
    if(req.url!==GATEWAY_BACKEND_PATH||req.method!=='POST')return send(res,404,{error:'not-found'});
    if(req.headers.authorization!==`Bearer ${secret}`)return send(res,401,{error:'unauthorized'});
    try{
      const body=await readJson(req);
      if(body.tool!=='pay_invoice'||body.resource!=='invoice:demo'||body.action!=='pay'||
         typeof body.operationId!=='string'||!Number.isSafeInteger(body.args?.amount_cents)||
         body.args.amount_cents>20_000||body.args.amount_cents<1||body.args.currency!=='EUR'||body.args.recipient!=='supplier_demo')
        return send(res,403,{error:'fixture-denied'});
      if(committed.has(body.operationId))return send(res,409,{error:'duplicate-operation'});
      committed.add(body.operationId);
      return send(res,200,{status:'simulated'});
    }catch{return send(res,400,{error:'invalid-request'});}
  });
}
