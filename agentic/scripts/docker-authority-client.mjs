/** Runs inside an agent-only network namespace in Docker Compose. No real tools. */
import {readFileSync} from 'node:fs';
const request=JSON.parse(readFileSync('/run/agent/request.json','utf8'));
async function waitGateway(){for(let i=0;i<40;i++){
  try{const r=await fetch('http://gateway:8098/healthz',{signal:AbortSignal.timeout(200)});if(r.ok)return;}catch{};
  await new Promise(r=>setTimeout(r,100));
}throw Error('gateway did not start');}
async function post(body){return fetch('http://gateway:8098/execute',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(2500)});}
await waitGateway();
let directBlocked=false;
try{await fetch('http://backend:8099/internal/execute',{method:'POST',headers:{'content-type':'application/json'},body:'{}',signal:AbortSignal.timeout(1000)});}catch{directBlocked=true;}
const unauthorized=await post({capability:request.capability});
const permitted=await post(request);
const replay=await post(request);
const results={directBlocked,unauthorized:unauthorized.status,permitted:permitted.status,replay:replay.status};
const pass=directBlocked&&unauthorized.status===403&&permitted.status===200&&replay.status===403;
console.log(JSON.stringify({test:'faraday-authority-docker-lab',pass,results}));
if(!pass)process.exitCode=1;
