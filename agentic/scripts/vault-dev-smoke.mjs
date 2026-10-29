/** Runs ONLY against a disposable Vault dev instance on loopback. No real credentials.
 * The CI root token is test-only, ephemeral and never logged.
 */
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes} from 'node:crypto';
import assert from 'node:assert/strict';
import {createVaultKv2SecretProvider} from '../lib/vault-kv2-secret-provider.js';
const baseUrl=process.env.FARADAY_TEST_VAULT_URL||'http://127.0.0.1:18200';
if(!/^http:\/\/127\.0\.0\.1:\d+$/.test(baseUrl))throw Error('Vault dev test requires literal loopback HTTP');
const token=process.env.FARADAY_TEST_VAULT_TOKEN;
if(!token||token.length<12)throw Error('Missing test-only Vault dev token');
const root=mkdtempSync(join(tmpdir(),'faraday-real-vault-ci-'));
const tokenFile=join(root,'vault-token');writeFileSync(tokenFile,token,{mode:0o600});
let step='start';
async function api(path,method='GET',body=null){
 const response=await fetch(baseUrl+path,{method,headers:{'x-vault-token':token,'content-type':'application/json'},
  body:body===null?undefined:JSON.stringify(body),redirect:'manual',signal:AbortSignal.timeout(4000)});
 if(!response.ok)throw Error('Vault dev API operation failed at '+step+' HTTP '+response.status);
 return response.json().catch(()=>({}));
}
try{
 let healthy=false;
 for(let i=0;i<35;i++){
  try{const response=await fetch(baseUrl+'/v1/sys/health',{signal:AbortSignal.timeout(1000)});if(response.ok){healthy=true;break}}catch{}
  await new Promise(r=>setTimeout(r,350));
 }
 if(!healthy)throw Error('Vault dev instance was not ready');
 const provider=createVaultKv2SecretProvider({baseUrl,mount:'secret',secretPath:'gateway/backend',tokenFile,allowLoopbackHttp:true});
 const first=randomBytes(40).toString('hex'),second=randomBytes(40).toString('hex');
 step='write-initial';await api('/v1/secret/data/gateway/backend','POST',{data:{backend_credential:first}});
 step='read-initial';assert.equal(await provider(),first);
 step='rotate';await api('/v1/secret/data/gateway/backend','POST',{data:{backend_credential:second}});
 step='read-rotated';assert.equal(await provider(),second);
 step='revoke-token';await api('/v1/auth/token/revoke-self','POST',{});
 step='read-after-revocation';await assert.rejects(provider(),/vault-credential-unavailable/);
 console.log(JSON.stringify({kind:'faraday-real-vault-kv2-dev',status:'pass',
  checks:['official-api-read','rotate-version','token-revocation-denied'],
  scope:'HashiCorp Vault dev mode on localhost; no real secrets, no production IAM, no lease renewal'}));
}finally{rmSync(root,{recursive:true,force:true});}
