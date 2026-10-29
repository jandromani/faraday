/** Official HashiCorp Vault dev-mode AppRole security acceptance.
 * Disposable loopback instance only. The root token bootstraps an AppRole,
 * but the gateway provider NEVER receives that root token.
 */
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes} from 'node:crypto';
import assert from 'node:assert/strict';
import {createVaultKv2SecretProvider} from '../lib/vault-kv2-secret-provider.js';

const baseUrl=process.env.FARADAY_TEST_VAULT_URL||'http://127.0.0.1:18200';
if(!/^http:\/\/127\.0\.0\.1:\d+$/.test(baseUrl))throw Error('Vault dev test requires literal loopback HTTP');
const rootToken=process.env.FARADAY_TEST_VAULT_TOKEN;
if(typeof rootToken!=='string'||rootToken.length<12)throw Error('Missing disposable Vault dev bootstrap token');
const root=mkdtempSync(join(tmpdir(),'faraday-vault-approle-'));
const tokenFile=join(root,'gateway-token');
let phase='bootstrap';
const api=async (path,{method='GET',token=rootToken,body,expect=[200,204]}={})=>{
  let response;
  try{
    response=await fetch(baseUrl+path,{method,redirect:'error',headers:{
      'x-vault-token':token,'content-type':'application/json',accept:'application/json'
    },body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(5000)});
  }catch{throw Error('Vault unavailable during '+phase);}
  const status=response.status;
  // Error bodies may include sensitive details; do not log them.
  if(!expect.includes(status)){try{await response.body?.cancel();}catch{}throw Error('Vault unexpected status during '+phase+': '+status);}
  if(status===204){try{await response.body?.cancel();}catch{}return {};}
  return response.json().catch(()=>{throw Error('Invalid Vault JSON during '+phase);});
};
const valid=token=>typeof token==='string'&&/^[A-Za-z0-9._~-]{8,2048}$/.test(token);
const login=async roleId=>{
  phase='issue-secret-id';
  const generated=await api('/v1/auth/approle/role/faraday-gateway/secret-id',{method:'POST',body:{}});
  const secretId=generated?.data?.secret_id;
  if(typeof secretId!=='string'||secretId.length<10)throw Error('Invalid Vault AppRole secret-id');
  phase='approle-login';
  const result=await api('/v1/auth/approle/login',{method:'POST',body:{role_id:roleId,secret_id:secretId}});
  const issued=result?.auth?.client_token;
  if(!valid(issued)||issued===rootToken)throw Error('Vault did not mint a separate scoped token');
  return issued;
};
try{
  let ready=false;
  for(let i=0;i<35;i++){
    try{const response=await fetch(baseUrl+'/v1/sys/health',{signal:AbortSignal.timeout(1000)});if(response.ok){ready=true;break;}}catch{}
    await new Promise(resolve=>setTimeout(resolve,350));
  }
  if(!ready)throw Error('Official Vault dev instance did not become healthy');

  phase='bootstrap-policy';
  await api('/v1/sys/policies/acl/faraday-gateway',{method:'PUT',body:{
    policy:'path "secret/data/gateway/backend" { capabilities = ["read"] }'
  }});
  phase='enable-approle';
  await api('/v1/sys/auth/approle',{method:'POST',body:{type:'approle'}});
  phase='configure-approle';
  await api('/v1/auth/approle/role/faraday-gateway',{method:'POST',body:{
    token_policies:['faraday-gateway'],token_no_default_policy:true,
    token_ttl:'90s',token_max_ttl:'180s',secret_id_num_uses:1,token_num_uses:0
  }});
  phase='fetch-role-id';
  const roleId=(await api('/v1/auth/approle/role/faraday-gateway/role-id'))?.data?.role_id;
  if(typeof roleId!=='string'||roleId.length<10)throw Error('Invalid Vault AppRole role-id');

  const first=randomBytes(40).toString('hex'),second=randomBytes(40).toString('hex');
  phase='seed';
  await api('/v1/secret/data/gateway/backend',{method:'POST',body:{data:{backend_credential:first}}});
  await api('/v1/secret/data/other/backend',{method:'POST',body:{data:{backend_credential:second}}});

  const scoped=await login(roleId);
  writeFileSync(tokenFile,scoped,{flag:'wx',mode:0o600});
  const provider=createVaultKv2SecretProvider({baseUrl,mount:'secret',
    secretPath:'gateway/backend',tokenFile,allowLoopbackHttp:true});

  phase='scoped-read';
  assert.equal(await provider(),first,'scoped AppRole cannot read its only allowed secret');
  phase='deny-other-secret';
  await api('/v1/secret/data/other/backend',{token:scoped,expect:[403]});
  phase='deny-admin';
  await api('/v1/sys/mounts',{token:scoped,expect:[403]});
  phase='deny-secret-write';
  await api('/v1/secret/data/gateway/backend',{token:scoped,method:'POST',
    body:{data:{backend_credential:'tamper'}},expect:[403]});

  phase='rotate-secret';
  await api('/v1/secret/data/gateway/backend',{method:'POST',body:{data:{backend_credential:second}}});
  assert.equal(await provider(),second,'provider did not observe root-authorized secret rotation');

  phase='revoke-scoped-token';
  await api('/v1/auth/token/revoke',{method:'POST',body:{token:scoped}});
  phase='deny-after-revocation';
  await assert.rejects(provider(),/vault-credential-unavailable/);

  const replacement=await login(roleId);
  writeFileSync(tokenFile,replacement,{mode:0o600});
  phase='new-token-recovers';
  assert.equal(await provider(),second,'fresh AppRole token did not restore allowed read');
  phase='revoke-replacement';
  await api('/v1/auth/token/revoke',{method:'POST',body:{token:replacement}});

  console.log(JSON.stringify({kind:'faraday-vault-approle-official-dev',result:'pass',
    controls:['scoped-kv2-read','nonroot-workload-token','deny-other-secret','deny-sys-admin',
      'deny-secret-write','read-rotated-version','deny-revoked-token','reissue-scoped-token'],
    scope:'Official Vault dev-mode AppRole on loopback; no production identity or lease management'}));
}finally{rmSync(root,{recursive:true,force:true});}
