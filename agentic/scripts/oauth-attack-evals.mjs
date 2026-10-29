#!/usr/bin/env node
/** Fully synthetic and offline token attack matrix; never connects to an IdP. */
import {generateKeyPairSync,sign} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {writeFileSync} from 'node:fs';
import {PinnedOAuthResource} from '../lib/mcp-oauth-resource.js';
const issuer='https://issuer.example.test',resource='https://gateway.example.test/mcp',now=1800000000;
const key=generateKeyPairSync('ed25519'),publicJwk={...key.publicKey.export({format:'jwk'}),kid:'test',alg:'EdDSA'};
const verifier=new PinnedOAuthResource({issuer,resource,publicJwks:[publicJwk],clock:()=>now});
const b64=x=>Buffer.from(JSON.stringify(x)).toString('base64url');
function mint(claims={},header={}){const h=b64({alg:'EdDSA',typ:'at+jwt',kid:'test',...header});
  const p=b64({iss:issuer,aud:resource,iat:now-10,exp:now+300,sub:'lab-agent',client_id:'lab-client',scope:'mcp:tools:read mcp:tools:execute',...claims});
  return h+'.'+p+'.'+sign(null,Buffer.from(h+'.'+p),key.privateKey).toString('base64url');}
const classes=[
{label:'valid-read',allowed:true,scope:'mcp:tools:read',make:()=>mint()},
{label:'valid-execute',allowed:true,scope:'mcp:tools:execute',make:()=>mint()},
{label:'wrong-audience',allowed:false,scope:'mcp:tools:execute',make:()=>mint({aud:'https://attacker.test/mcp'})},
{label:'expired',allowed:false,scope:'mcp:tools:execute',make:()=>mint({exp:now-1})},
{label:'wrong-issuer',allowed:false,scope:'mcp:tools:execute',make:()=>mint({iss:'https://attacker.test'})},
{label:'read-scope-escalation',allowed:false,scope:'mcp:tools:execute',make:()=>mint({scope:'mcp:tools:read'})},
{label:'forged-signature',allowed:false,scope:'mcp:tools:execute',make:()=>{const p=mint().split('.');p[2]=(p[2][0]==='A'?'B':'A')+p[2].slice(1);return p.join('.');}},
{label:'unknown-kid',allowed:false,scope:'mcp:tools:execute',make:()=>mint({}, {kid:'rogue'})}
];
const failures=[],counts={},latencies=[];
for(const c of classes){let passed=0;for(let i=0;i<25;i++){
 const start=performance.now();let allowed=true;try{verifier.verifyAuthorization('Bearer '+c.make(),c.scope);}catch{allowed=false;}
 latencies.push(performance.now()-start);
 if(allowed!==c.allowed)failures.push({class:c.label,case:i});else passed++;
}counts[c.label]={passed,total:25};}
const sorted=latencies.sort((a,b)=>a-b);
const report={kind:'faraday-oauth-evals',release:'0.99.3',total:200,passed:200-failures.length,failures,classes:counts,
 latencyMs:{median:Number(sorted[100].toFixed(3)),p95:Number(sorted[189].toFixed(3))},
 limitations:['Signed synthetic tokens only','Not an independent identity-provider conformance test','Local cryptographic microbenchmarks, not gateway p95']};
const out=process.argv.indexOf('--out');if(out>=0){if(!process.argv[out+1])throw Error('Missing report path');writeFileSync(process.argv[out+1],JSON.stringify(report,null,2)+'\n',{flag:'wx'});}
console.log(JSON.stringify(report,null,2));if(failures.length)process.exitCode=1;
