/** Security-negative test from an agent with no capability, approval, signing or backend secret. */
import {existsSync} from 'node:fs';
const deniedSecrets=['/run/faraday/backend-secret','/run/agent/agent-private.pem','/run/state/journal.sqlite',
 '/run/backend-state/backend-attestation-private.pem'].every(p=>!existsSync(p));
const body=JSON.stringify({jsonrpc:'2.0',id:77,method:'tools/call',params:{name:'pay_invoice',
 arguments:{amount_cents:9500,currency:'EUR',recipient:'supplier_demo'},
 _meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28'}}});
const request=async url=>{
 try{return await fetch(url,{method:'POST',headers:{'content-type':'application/json',
    'mcp-protocol-version':'2026-07-28','mcp-method':'tools/call','mcp-name':'pay_invoice'},body,
    signal:AbortSignal.timeout(1500)});}catch{return null;}
};
let health=false;for(let i=0;i<35;i++){
 try{health=(await fetch('http://gateway:8098/healthz',{signal:AbortSignal.timeout(400)})).ok;if(health)break;}catch{}
 await new Promise(r=>setTimeout(r,200));
}
if(!health)throw Error('Gateway not ready for attack fixture');
const backendDirect=await request('http://backend:8099/internal/execute');
const gatewayAnonymous=await request('http://gateway:8098/mcp');
const gatewayForgery=await fetch('http://gateway:8098/mcp',{method:'POST',headers:{'content-type':'application/json',
  'mcp-protocol-version':'2026-07-28','mcp-method':'tools/call','mcp-name':'pay_invoice',
  'x-faraday-capability':'rogue','x-faraday-proof':'rogue','x-faraday-approvals':'rogue'},
 body,signal:AbortSignal.timeout(2000)});
const result={kind:'faraday-rogue-mcp-reference-attack',
 checks:{noCredentialVolumes:deniedSecrets,backendDirectUnreachable:backendDirect===null,
 anonymousDenied:gatewayAnonymous?.status===403,forgeryDenied:![200,201,202].includes(gatewayForgery.status)},
 caveat:'Only the Docker reference network; neither arbitrary workload isolation nor an external pentest'};
result.pass=Object.values(result.checks).every(Boolean);
console.log(JSON.stringify(result));if(!result.pass)process.exitCode=1;
