/** Disposable real HashiCorp Vault KV v2 dev instance on loopback; no production secrets. */
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes} from 'node:crypto';
import assert from 'node:assert/strict';
import {createVaultKv2SecretProvider} from '../lib/vault-kv2-secret-provider.js';
const baseUrl=process.env.FARADAY_TEST_VAULT_URL||'http://127.0.0.1:18200';
if(!/^http:\/\/127\.0\.0\.1:\d+$/.test(baseUrl))throw Error('Only local Vault dev accepted');
const token=process.env.FARADAY_TEST_VAULT_TOKEN;
if(!token||token.length<12)throw Error('Missing test-only Vault token');
const root=mkdtempSync(join(tmpdir(),'faraday-vault-dev-ci-')),tokenFile=join(root,'vault-token');
writeFileSync(tokenFile,token,{mode:0o600});
let step='startup';
async function api(path,method='GET',body=null){
 const res=await fetch(baseUrl+path,{method,headers:{'x-vault-token':token,'content-type':'application/json'},body:body===null?undefined:JSON.stringify(body),redirect:'manual',signal:AbortSignal.timeout(4000)});
 if(!res.ok)throw Error('Vault dev HTTP '+res.status+' during '+step);
 return res.json().catch(()=>({}));
}
try{
 let ready=false;
 for(let i=0;i<35;i++){
  try{const response=await fetch(baseUrl+'/v1/sys/health',{signal:AbortSignal.timeout(1000)});if(response.ok){ready=true;break;}}catch{}
  await new Promise(r=>setTimeout(r,350));
 }
 if(!ready)throw Error('Vault dev not ready');
 const resolveSecret=createVaultKv2SecretProvider({baseUrl,mount:'secret',secretPath:'gateway/backend',tokenFile,allowLoopbackHttp:true});
 const a=randomBytes(40).toString('hex'),b=randomBytes(40).toString('hex');
 step='create';await api('/v1/secret/data/gateway/backend','POST',{data:{backend_credential:a}});
 step='read';assert.equal(await resolveSecret(),a);
 step='rotate';await api('/v1/secret/data/gateway/backend','POST',{data:{backend_credential:b}});
 step='read-rotated';assert.equal(await resolveSecret(),b);
 step='revoke';await api('/v1/auth/token/revoke-self','POST',{});
 step='fail-closed';await assert.rejects(resolveSecret(),/vault-credential-unavailable/);
 console.log(JSON.stringify({kind:'faraday-official-vault-dev',status:'pass',checks:['read','rotation','token-revocation'],scope:'disposable dev mode only'}));
}finally{rmSync(root,{recursive:true,force:true});}
