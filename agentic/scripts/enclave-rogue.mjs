import {existsSync,openSync,closeSync,unlinkSync,readFileSync} from 'node:fs';
import {isIP} from 'node:net';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';

const payload=JSON.stringify({jsonrpc:'2.0',id:77,method:'tools/call',params:{name:'pay_invoice',arguments:{amount_cents:9500,currency:'EUR',recipient:'supplier_demo'},_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28'}}});
const headers={'content-type':'application/json','mcp-protocol-version':'2026-07-28','mcp-method':'tools/call','mcp-name':'pay_invoice'};
function canOpenForWrite(path,flags){
  let descriptor;
  try{descriptor=openSync(path,flags,0o600);return true;}catch{return false;}
  finally{if(descriptor!==undefined){closeSync(descriptor);if(flags==='wx')unlinkSync(path);}}
}
function localChecks(){
  const status=readFileSync('/proc/self/status','utf8');
  const mounts=readFileSync('/proc/self/mountinfo','utf8').split('\n').map(line=>line.split(' '));
  const readOnly=path=>mounts.some(parts=>parts[4]===path&&parts[5]?.split(',').includes('ro'));
  return {
    noSecretFiles:['/run/faraday/backend-secret','/run/agent/agent-private.pem','/run/backend-state/backend-attestation-private.pem','/run/state/journal.sqlite'].every(path=>!existsSync(path)),
    sourceReadOnly:readOnly('/app')&&!canOpenForWrite('/app/package.json','r+'),
    rootReadOnly:readOnly('/')&&!canOpenForWrite(`/etc/faraday-probe-${process.pid}`,'wx'),
    nonRoot:typeof process.getuid==='function'&&process.getuid()!==0,
    noNewPrivileges:/^NoNewPrivs:\s+1\s*$/m.test(status),
    noCapabilities:/^CapEff:\s+0+\s*$/m.test(status)
  };
}
export async function probeEnclave({backendHost,egressHost,request=fetch,checks=localChecks()}={}){
  if(isIP(backendHost)!==4||isIP(egressHost)!==4)throw Error('Explicit IPv4 probe targets required');
  async function attempt(url,extra={}){
    try{return await request(url,{method:'POST',headers:{...headers,...extra},body:payload,signal:AbortSignal.timeout(1500)});}catch{return null;}
  }
  const backend=await attempt(`http://${backendHost}:8099/internal/execute`);
  const egress=await attempt(`http://${egressHost}:8097/`);
  const anonymous=await attempt('http://gateway:8098/mcp');
  const forged=await attempt('http://gateway:8098/mcp',{'x-faraday-capability':'rogue','x-faraday-proof':'rogue'});
  const result={...checks,backendDirectUnreachable:backend===null,externalTargetUnreachable:egress===null,anonymousDenied:anonymous?.status===403,forgeryDenied:forged?.status===403};
  return {pass:Object.values(result).every(value=>value===true),checks:result};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const result=await probeEnclave({backendHost:process.env.FARADAY_TEST_BACKEND_HOST,egressHost:process.env.FARADAY_TEST_EGRESS_HOST});
  console.log(JSON.stringify({kind:'synthetic-untrusted-tool',...result}));
  if(!result.pass)process.exitCode=1;
}