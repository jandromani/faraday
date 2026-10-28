/** Real Docker network bypass test, synthetic payment only. */
import {readFileSync} from 'node:fs';
import {createExecution} from '../lib/authority.js';
import {verifyReceipt} from '../lib/pilot-receipts.js';
import {AGENT,TOOL,RESOURCE,ACTION,ARGS} from '../lib/authority-fixture.js';
const capability=JSON.parse(readFileSync('/run/agent/capability.json','utf8')).capability;
const privatePem=readFileSync('/run/agent/agent-private.pem','utf8');
const publicPem=readFileSync('/run/agent/receipt.pub','utf8');
const backendPublicPem=readFileSync('/run/agent/backend.pub','utf8');
const BASE='http://gateway:8098';
const approvals=readFileSync('/run/agent/approvals.txt','utf8').trim();
for(let i=0;i<40;i++){
  try{if((await fetch(BASE+'/healthz',{signal:AbortSignal.timeout(300)})).ok)break;}catch{}
  if(i===39)throw Error('Gateway failed to start');
  await new Promise(resolve=>setTimeout(resolve,150));
}
let bypassDenied=false;try{await fetch('http://backend:8099/internal/execute',{method:'POST',headers:{'content-type':'application/json'},body:'{}',signal:AbortSignal.timeout(1000)});}catch{bypassDenied=true;}
const VERSION='2026-07-28';
const proof=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,capability,agentPrivatePem:privatePem});
async function invoke(withAuth,withApprovals=true){
  const msg={jsonrpc:'2.0',id:1,method:'tools/call',params:{name:TOOL,arguments:ARGS,_meta:{'io.modelcontextprotocol/protocolVersion':VERSION}}};
  const headers={'content-type':'application/json','mcp-protocol-version':VERSION,'mcp-method':'tools/call','mcp-name':TOOL};
  if(withAuth){headers['x-faraday-capability']=capability;headers['x-faraday-proof']=Buffer.from(JSON.stringify(proof)).toString('base64url');
    if(withApprovals)headers['x-faraday-approvals']=approvals;}
  const response=await fetch(BASE+'/mcp',{method:'POST',headers,body:JSON.stringify(msg),signal:AbortSignal.timeout(3000)});
  return {status:response.status,data:await response.json()};
}
const anonymous=await invoke(false);const noApproval=await invoke(true,false);const allowed=await invoke(true);const replay=await invoke(true);
const receipt=allowed.data.result?.structuredContent?.receipt;
const verified=Boolean(receipt&&verifyReceipt({publicPem,receipt,backendPublicPem}).backendVerified);
const pass=bypassDenied&&anonymous.status===403&&noApproval.status===403&&allowed.status===200&&replay.status===403&&verified;
console.log(JSON.stringify({kind:'faraday-secure-pilot-docker',pass,
  checks:{bypassDenied,anonymous:anonymous.status,noApproval:noApproval.status,allowed:allowed.status,replay:replay.status,verified},
  note:'Only for this Docker network; no real payments or arbitrary production tools.'}));
if(!pass)process.exitCode=1;
