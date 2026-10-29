/** Read-only HashiCorp Vault KV v2 credential provider, no caching/fallback. */
import {lstatSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
const segment=s=>typeof s==='string'&&/^[A-Za-z0-9_-]{1,90}$/.test(s);
const fail=()=>{throw Error('vault-credential-unavailable');};
export function createVaultKv2SecretProvider({baseUrl,mount='secret',secretPath,field='backend_credential',tokenFile,namespace=null,allowLoopbackHttp=false,timeoutMs=3000,maxResponseBytes=8192,fetchFn=fetch}={}){
  if(typeof baseUrl!=='string'||!segment(mount)||typeof secretPath!=='string'||!secretPath.split('/').every(segment)||!segment(field)||typeof tokenFile!=='string'||!tokenFile||(namespace!==null&&!segment(namespace))||!Number.isSafeInteger(timeoutMs)||timeoutMs<200||timeoutMs>20000||!Number.isSafeInteger(maxResponseBytes)||maxResponseBytes<512||maxResponseBytes>65536||typeof fetchFn!=='function')throw Error('invalid-vault-configuration');
  let base;try{base=new URL(baseUrl);}catch{throw Error('invalid-vault-url');}
  const loopback=['localhost','127.0.0.1','[::1]'].includes(base.hostname);
  if(base.username||base.password||base.search||base.hash||base.pathname!=='/'||!(base.protocol==='https:'||(allowLoopbackHttp&&loopback&&base.protocol==='http:')))throw Error('invalid-vault-url');
  const endpoint=new URL('/v1/'+mount+'/data/'+secretPath,base).href,location=resolve(tokenFile);
  return async function resolveVaultCredential(){
    let token;
    try{
      const stat=lstatSync(location);
      if(!stat.isFile()||stat.isSymbolicLink()||stat.size>4096||stat.size<8||(process.platform!=='win32'&&(stat.mode&0o077)!==0))fail();
      token=readFileSync(location,'utf8').trim();
      if(!/^[A-Za-z0-9._~-]{8,2048}$/.test(token))fail();
    }catch{fail();}
    let result;
    try{result=await fetchFn(endpoint,{method:'GET',redirect:'manual',headers:{'x-vault-token':token,'accept':'application/json',...(namespace?{'x-vault-namespace':namespace}:{})},signal:AbortSignal.timeout(timeoutMs)});}
    catch{fail();}finally{token=null;}
    if(result.status!==200||!result.body||result.headers.get('content-type')?.split(';')[0].trim()!=='application/json'){try{await result.body?.cancel();}catch{}fail();}
    const length=result.headers.get('content-length');
    if(length!==null&&(!/^\d+$/.test(length)||Number(length)>maxResponseBytes)){try{await result.body.cancel();}catch{}fail();}
    let bytes=0;const chunks=[],reader=result.body.getReader();
    try{while(true){const next=await reader.read();if(next.done)break;bytes+=next.value.byteLength;if(bytes>maxResponseBytes)fail();chunks.push(next.value);}}
    catch{try{await reader.cancel();}catch{}fail();}finally{reader.releaseLock();}
    let body;try{body=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{fail();}
    const value=body?.data?.data?.[field];
    if(typeof value!=='string'||value.length<32||value.length>4096||!/^[A-Za-z0-9_+=./:-]+$/.test(value)||!Number.isInteger(body?.data?.metadata?.version)||body.data.metadata.version<1)fail();
    return value;
  };
}
