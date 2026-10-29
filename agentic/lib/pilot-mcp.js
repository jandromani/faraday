/** Secure Pilot MCP HTTP endpoint.
 * Limited JSON-response, single-tool subset of MCP (2025-11-25 / 2026-07-28).
 * Security headers are injected by a TRUSTED harness/adapter, never by an LLM.
 * Not full MCP OAuth, attested workloads, or arbitrary remote tool isolation.
 */
import http from 'node:http';
import {AuthorityError,canonical,digest} from './authority.js';
import {readJson} from './authority-gateway.js';
import {signReceipt} from './pilot-receipts.js';
import {verifyBackendAttestation} from './backend-attestation.js';
import {decodeApprovals,verifyApprovals} from './approvals.js';
import {OAuthBoundaryError} from './mcp-oauth-resource.js';
import {createFailClosedGatewayPolicyPort} from './gateway-policy-port.js';
import {pilotBackendEndpoint} from './pilot-endpoint.js';
const VERSION='2026-07-28',PREVIOUS='2025-11-25';
const PATH='/mcp';
const json=(res,status,data)=>{const bytes=Buffer.from(JSON.stringify(data));res.writeHead(status,{'content-type':'application/json','content-length':bytes.length,'cache-control':'no-store','x-content-type-options':'nosniff'});res.end(bytes);};
const rpcError=(id,code,message)=>({jsonrpc:'2.0',id,error:{code,message}});
const rpcResult=(id,result)=>({jsonrpc:'2.0',id,result});
const TOOL_DESCRIPTION='Simulate a fake invoice payment. Synthetic fixture only; never transfers money.';
const TOOLS=[{name:'pay_invoice',description:TOOL_DESCRIPTION,inputSchema:{type:'object',additionalProperties:false,
  properties:{amount_cents:{type:'integer',minimum:1,maximum:20000},currency:{type:'string',enum:['EUR']},recipient:{type:'string',enum:['supplier_demo']}},required:['amount_cents','currency','recipient']}}];
const decode=(header)=>{
  if(typeof header!=='string'||header.length>15000||!/^[A-Za-z0-9_-]+$/.test(header))throw new AuthorityError('invalid-proof-header');
  const bytes=Buffer.from(header,'base64url');if(bytes.toString('base64url')!==header||bytes.length>8192)throw new AuthorityError('invalid-proof-header');
  let x;try{x=JSON.parse(bytes.toString('utf8'));}catch{throw new AuthorityError('invalid-proof-header');}
  return x;
};
async function bounded(response,maxBytes=8192){
  const claimed=Number(response.headers.get('content-length'));
  if(Number.isFinite(claimed)&&claimed>maxBytes)throw new Error('oversized-upstream');
  const reader=response.body?.getReader();if(!reader)throw new Error('invalid-upstream');
  const chunks=[];let size=0;
  try{while(true){const {value,done}=await reader.read();if(done)break;size+=value.length;if(size>maxBytes)throw new Error('oversized-upstream');chunks.push(value);}}
  finally{reader.releaseLock();}
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
export function createSecurePilotGateway({gate,backendUrl,backendSecret,backendSecretProvider=null,journal,receiptPrivatePem,backendPublicPem,
      fetchFn=fetch,onEvent=()=>{},now=()=>Math.floor(Date.now()/1000),allowedOrigins=[],
  approvalConfig=null,sentinel=null,budget=null,oauthResource=null,externalPolicy=null,allowInsecureBackend=false}){
  const endpoint=pilotBackendEndpoint(backendUrl,{allowInsecureBackend});
  if(((!backendSecretProvider && (typeof backendSecret!=='string'||backendSecret.length<32)) || (backendSecretProvider&&typeof backendSecretProvider!=='function'))||!gate||!journal||typeof journal.reserve!=='function'||!receiptPrivatePem||!backendPublicPem)throw Error('Secure Pilot requires gate, journal, gateway/backend signing identities and service credential');
  if(approvalConfig && (!approvalConfig.approverKeys||!Number.isSafeInteger(approvalConfig.quorum)||approvalConfig.quorum<1))throw Error('Invalid approval configuration');
  const evaluateExternalPolicy=externalPolicy===null?null:createFailClosedGatewayPolicyPort(externalPolicy);
  return http.createServer(async(req,res)=>{
    if(req.url==='/healthz'&&req.method==='GET')return json(res,200,{service:'faraday-secure-pilot',status:'ok'});
    if(oauthResource && req.method==='GET' && ['/.well-known/oauth-protected-resource/mcp','/.well-known/oauth-protected-resource'].includes(req.url)){
      return json(res,200,oauthResource.metadata);
    }
    if(req.url===PATH&&req.method!=='POST'){
      res.setHeader('allow','POST');return json(res,405,{error:'method-not-allowed'});
    }
    if(req.url!==PATH)return json(res,404,{error:'not-found'});
    const origin=req.headers.origin;
    if(origin&&!allowedOrigins.includes(origin))return json(res,403,{error:'invalid-origin'});
    let msg;
    try{msg=await readJson(req);
      if(msg.jsonrpc!=='2.0'||(!Number.isSafeInteger(msg.id)&&typeof msg.id!=='string')||typeof msg.method!=='string')throw Error('invalid-rpc');
      if(msg.id===null||msg.method.length>100)throw Error('invalid-rpc');
      if(msg.method==='tools/call' || msg.method==='tools/list' || msg.method==='server/discover'){
        const ver=req.headers['mcp-protocol-version'];
        if(ver===VERSION){
          if(msg.params?._meta?.['io.modelcontextprotocol/protocolVersion']!==VERSION ||
             req.headers['mcp-method']!==msg.method ||
             (msg.method==='tools/call'&&req.headers['mcp-name']!==msg.params?.name))throw Error('protocol-header-mismatch');
        }else if(ver!==PREVIOUS)throw Error('unsupported-protocol-version');
      }
    }catch{return json(res,400,rpcError(msg?.id??null,-32600,'Invalid MCP request'));}
    // Scope is derived from the authenticated JSON-RPC body, NEVER the client-supplied
    // Mcp-Method header: legacy clients do not include it (header/body confusion).
    let oauthIdentity=null;
    if(oauthResource){
      const scope=msg.method==='tools/call'?oauthResource.executeScope:oauthResource.readScope;
      try{oauthIdentity=oauthResource.verifyAuthorization(req.headers.authorization,scope);}catch(e){
        const status=e instanceof OAuthBoundaryError?e.status:401;
        res.setHeader('www-authenticate',oauthResource.challenge(scope,status===403?'insufficient_scope':'invalid_token'));
        return json(res,status,{error:status===403?'insufficient_scope':'invalid_token'});
      }
    }
    if(msg.method==='server/discover'&&req.headers['mcp-protocol-version']!==VERSION)return json(res,400,rpcError(msg.id,-32600,'Modern protocol version required'));
    if(msg.method==='server/discover')return json(res,200,rpcResult(msg.id,{resultType:'complete',
      supportedVersions:[VERSION,PREVIOUS],capabilities:{tools:{}},
      _meta:{'io.modelcontextprotocol/serverInfo':{name:'faraday-secure-pilot',version:'0.99.3'}},
      ttlMs:0,cacheScope:'private'}));
    if(msg.method==='initialize'&&msg.params?.protocolVersion===VERSION)return json(res,400,rpcError(msg.id,-32022,'Modern MCP does not use initialize'));
    if(msg.method==='initialize'&&msg.params?.protocolVersion!==PREVIOUS)return json(res,400,rpcError(msg.id,-32022,'Unsupported protocol version'));
    if(msg.method==='initialize')return json(res,200,rpcResult(msg.id,{protocolVersion:PREVIOUS,
      capabilities:{tools:{}},serverInfo:{name:'faraday-secure-pilot',version:'0.99.3'}}));
    if(msg.method==='tools/list')return json(res,200,rpcResult(msg.id,
      req.headers['mcp-protocol-version']===VERSION?{resultType:'complete',tools:TOOLS,ttlMs:0,cacheScope:'private'}:{tools:TOOLS}));
    if(msg.method!=='tools/call')return json(res,404,rpcError(msg.id,-32601,'Method not found'));
    const remote=req.socket.remoteAddress??'unknown';
    try{if(sentinel?.isBlocked(remote))return json(res,403,rpcError(msg.id,-32003,'FARADAY execution suspended'));}
    catch{return json(res,503,rpcError(msg.id,-32004,'FARADAY incident ledger unavailable'));}
    let auth;
    try{
      if(msg.params?.name!=='pay_invoice'||!msg.params.arguments||typeof msg.params.arguments!=='object'||Array.isArray(msg.params.arguments))throw new AuthorityError('unknown-tool');
      const capability=req.headers['x-faraday-capability'];
      const proof=decode(req.headers['x-faraday-proof']);
      if(typeof capability!=='string'||capability.length>16000)throw new AuthorityError('invalid-capability');
      // Approval is evaluated BEFORE spending the capability, and is bound to the exact signed intent.
      if(digest(msg.params.arguments)!==digest(proof.payload?.args))throw new AuthorityError('argument-mismatch');
      if(evaluateExternalPolicy){
        const decision=await evaluateExternalPolicy({agent:proof.payload?.agent,method:msg.method,resource:proof.payload?.resource});
        if(!decision.allowed)throw new AuthorityError('external-policy-denied');
        if(sentinel?.isBlocked(remote))throw new AuthorityError('execution-suspended');
        if(oauthResource)oauthIdentity=oauthResource.verifyAuthorization(req.headers.authorization,oauthResource.executeScope);
      }
      if(approvalConfig){
        verifyApprovals({bundle:decodeApprovals(req.headers['x-faraday-approvals']),
          approverKeys:approvalConfig.approverKeys,quorum:approvalConfig.quorum,requiredRoles:approvalConfig.requiredRoles??[],
          capability,agent:proof.payload.agent,tool:proof.payload.tool,resource:proof.payload.resource,
          action:proof.payload.action,args:msg.params.arguments,now:now()});
      }
          if(oauthResource&&oauthIdentity.subject!==proof.payload?.agent)throw new AuthorityError('oauth-agent-mismatch');
      auth=gate.authorize({capability,proof});
      if(oauthResource && oauthIdentity.subject!==auth.agent)throw new AuthorityError('oauth-agent-mismatch');
      if(auth.tool!=='pay_invoice'||auth.resource!=='invoice:demo'||auth.action!=='pay')throw new AuthorityError('invalid-scope');
      // Consume the quota before any backend side effect; failures burn this capability (fail-closed).
      budget?.consume(auth.agent);
      journal.reserve(auth.jti,digest({tool:auth.tool,resource:auth.resource,action:auth.action,args:auth.args}));
    }catch(e){const reason=e instanceof AuthorityError?e.code:'invalid-request';
      try{onEvent({status:'denied',reason});}catch{}
      try{sentinel?.record('deny',remote,reason);}catch{return json(res,503,rpcError(msg.id,-32004,'FARADAY incident ledger unavailable'));}
      return json(res,403,rpcError(msg.id,-32003,'FARADAY authority denied'));}
    let outcome='upstream-uncertain',responseHash=null,backendAttestation=null;
    try{
      const currentSecret=backendSecretProvider?await backendSecretProvider():backendSecret;
      if(typeof currentSecret!=='string'||currentSecret.length<32)throw Error('credential-unavailable');
      const upstream=await fetchFn(endpoint,{method:'POST',redirect:'error',signal:AbortSignal.timeout(3000),headers:{
        'content-type':'application/json','authorization':`Bearer ${currentSecret}`},body:JSON.stringify({
        tool:auth.tool,resource:auth.resource,action:auth.action,args:auth.args,operationId:auth.jti})});
      const result=await bounded(upstream);
      const expected=digest({tool:auth.tool,resource:auth.resource,action:auth.action,args:auth.args});
      if(upstream.status===200 && result.status==='simulated' && result.operationId===auth.jti && result.requestHash===expected){
        verifyBackendAttestation({publicPem:backendPublicPem,attestation:result.attestation,operationId:auth.jti,requestHash:expected});
        outcome='simulated';backendAttestation=result.attestation;responseHash=digest(result.attestation);
      }
    }catch{outcome='upstream-uncertain';}
    let receipt;
    try{
      receipt=signReceipt({privatePem:receiptPrivatePem,claims:{version:1,operationId:auth.jti,agent:auth.agent,
        tool:auth.tool,resource:auth.resource,action:auth.action,argsHash:digest(auth.args),requestHash:digest({tool:auth.tool,resource:auth.resource,action:auth.action,args:auth.args}),rule:auth.rule,
        outcome,responseHash,backendAttestation,observedAt:now()}});
      journal.finish(auth.jti,outcome,receipt);
      sentinel?.record('allow',remote,outcome);
      onEvent({status:outcome,tool:auth.tool,agent:auth.agent,operationId:auth.jti});
    }catch{return json(res,503,rpcError(msg.id,-32004,'Execution journal unavailable'));}
    if(outcome!=='simulated')return json(res,503,rpcError(msg.id,-32005,`Backend outcome: ${outcome}; manual reconciliation required`));
    return json(res,200,rpcResult(msg.id,{...(req.headers['mcp-protocol-version']===VERSION?{resultType:'complete'}:{}),
      content:[{type:'text',text:'Synthetic invoice operation simulated; no real payment occurred.'}],
      isError:false,structuredContent:{status:outcome,operationId:auth.jti,receipt}}));
  });
}
