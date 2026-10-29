/** Rogue agent has no credentials or agent keys, only a read-only source mount. */
import {existsSync} from 'node:fs';
const noSecrets=['/run/faraday/backend-secret','/run/agent/agent-private.pem','/run/state/journal.sqlite','/run/backend-state/backend-attestation-private.pem'].every(x=>!existsSync(x));
const payload=JSON.stringify({jsonrpc:'2.0',id:77,method:'tools/call',params:{name:'pay_invoice',arguments:{amount_cents:9500,currency:'EUR',recipient:'supplier_demo'},_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28'}}});
const headers={'content-type':'application/json','mcp-protocol-version':'2026-07-28','mcp-method':'tools/call','mcp-name':'pay_invoice'};
async function invoke(url,more={}){try{return await fetch(url,{method:'POST',headers:{...headers,...more},body:payload,signal:AbortSignal.timeout(1500)});}catch{return null;}}
let health=false;
for(let i=0;i<35;i++){
 try{health=(await fetch('http://gateway:8098/healthz',{signal:AbortSignal.timeout(400)})).ok;if(health)break;}catch{}
 await new Promise(r=>setTimeout(r,200));
}
if(!health)throw Error('Gateway not ready for rogue-agent test');
const backend=await invoke('http://backend:8099/internal/execute');
const anonymous=await invoke('http://gateway:8098/mcp');
const forged=await invoke('http://gateway:8098/mcp',{'x-faraday-capability':'rogue','x-faraday-proof':'rogue','x-faraday-approvals':'rogue'});
const checks={noCredentialVolumes:noSecrets,backendDirectUnreachable:backend===null,anonymousDenied:anonymous?.status===403,forgeryDenied:Boolean(forged)&&![200,201,202].includes(forged.status)};
const pass=Object.values(checks).every(Boolean);
console.log(JSON.stringify({kind:'faraday-rogue-mcp-reference-attack',pass,checks,note:'Only this reference Docker topology; no claim of arbitrary production isolation'}));
if(!pass)process.exitCode=1;
