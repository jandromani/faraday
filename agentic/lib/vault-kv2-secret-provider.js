import {readKeyFile} from './authority.js';

const segment=value=>typeof value==='string'&&/^[A-Za-z0-9_-]{1,90}$/.test(value);
const fail=()=>{throw Error('vault-credential-unavailable');};

export function createVaultKv2SecretProvider({baseUrl,mount='secret',secretPath,field='backend_credential',tokenFile,namespace=null,allowLoopbackHttp=false,timeoutMs=3000,maxResponseBytes=8192,fetchFn=fetch}={}){
  if(typeof baseUrl!=='string'||!segment(mount)||typeof secretPath!=='string'||!secretPath.split('/').every(segment)||!segment(field)||typeof tokenFile!=='string'||!tokenFile||(namespace!==null&&!segment(namespace))||!Number.isSafeInteger(timeoutMs)||timeoutMs<200||timeoutMs>20000||!Number.isSafeInteger(maxResponseBytes)||maxResponseBytes<512||maxResponseBytes>65536||typeof fetchFn!=='function')throw Error('invalid-vault-configuration');
  let base;try{base=new URL(baseUrl);}catch{throw Error('invalid-vault-url');}
  const loopback=['localhost','127.0.0.1','[::1]'].includes(base.hostname);
  if(base.username||base.password||base.search||base.hash||base.pathname!=='/'||!(base.protocol==='https:'||(allowLoopbackHttp===true&&loopback&&base.protocol==='http:')))throw Error('invalid-vault-url');
  const endpoint=new URL('/v1/'+mount+'/data/'+secretPath,base).href;
  return async function resolveVaultCredential(){
    let token;
    try{token=readKeyFile(tokenFile,{privateKey:true}).trim();if(!/^[A-Za-z0-9._~-]{8,2048}$/.test(token))fail();}catch{fail();}
    let response;
    try{response=await fetchFn(endpoint,{method:'GET',redirect:'error',headers:{'x-vault-token':token,accept:'application/json',...(namespace?{'x-vault-namespace':namespace}:{})},signal:AbortSignal.timeout(timeoutMs)});}
    catch{fail();}finally{token=null;}
    if(response.status!==200||!response.body||response.headers.get('content-type')?.split(';')[0].trim()!=='application/json'){try{await response.body?.cancel();}catch{}fail();}
    const length=response.headers.get('content-length');
    if(length!==null&&(!/^\d+$/.test(length)||Number(length)>maxResponseBytes)){try{await response.body.cancel();}catch{}fail();}
    let size=0;const chunks=[],reader=response.body.getReader();
    try{while(true){const {value,done}=await reader.read();if(done)break;size+=value.byteLength;if(size>maxResponseBytes)fail();chunks.push(value);}}
    catch{try{await reader.cancel();}catch{}fail();}finally{reader.releaseLock();}
    let body;try{body=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{fail();}
    const value=body?.data?.data?.[field];
    if(typeof value!=='string'||value.length<32||value.length>4096||!/^[A-Za-z0-9_+=./:-]+$/.test(value)||!Number.isSafeInteger(body?.data?.metadata?.version)||body.data.metadata.version<1)fail();
    return value;
  };
}