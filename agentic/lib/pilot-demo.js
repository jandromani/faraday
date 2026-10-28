import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fixture,AGENT,TOOL,RESOURCE,ACTION,ARGS} from './authority-fixture.js';
import {createExecution,newIdentity} from './authority.js';
import {ExecutionJournal,verifyReceipt} from './pilot-receipts.js';
import {DurableSyntheticStore,createDurableSyntheticBackend} from './pilot-backend.js';
import {createSecurePilotGateway} from './pilot-mcp.js';
const VERSION='2026-07-28';
async function start(server){await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));return `http://127.0.0.1:${server.address().port}`;}
const close=(server)=>new Promise(resolve=>server.close(resolve));
function makeCall(url,capability,proof,args=ARGS){
  const msg={jsonrpc:'2.0',id:7,method:'tools/call',params:{name:TOOL,arguments:args,_meta:{'io.modelcontextprotocol/protocolVersion':VERSION}}};
  return fetch(url+'/mcp',{method:'POST',headers:{'content-type':'application/json','mcp-protocol-version':VERSION,
    'mcp-method':'tools/call','mcp-name':TOOL,...(capability?{'x-faraday-capability':capability,'x-faraday-proof':Buffer.from(JSON.stringify(proof)).toString('base64url')}:{})},body:JSON.stringify(msg)});
}
export async function runPilotDemo(){
  const root=mkdtempSync(join(tmpdir(),'faraday-095-pilot-'));const f=fixture(root),receiptKey=newIdentity();
  const journal=new ExecutionJournal(join(root,'pilot-journal.sqlite'));
  const durableStore=new DurableSyntheticStore(join(root,'backend.sqlite'));
  const backend=createDurableSyntheticBackend({secret:f.backendSecret,store:durableStore});
  let gateway;
  try{
    const backendBase=await start(backend);
    gateway=createSecurePilotGateway({gate:f.gate,backendUrl:backendBase+'/internal/execute',backendSecret:f.backendSecret,
      journal,receiptPrivatePem:receiptKey.privatePem});
    const url=await start(gateway);
    const rogue=newIdentity();
    const forged=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,
      agentPrivatePem:rogue.privatePem,capability:f.capability});
    const stolen=(await makeCall(url,f.capability,forged)).status;
    const allowedResponse=await makeCall(url,f.capability,f.proof);const allowed=allowedResponse.status;
    const allowedJson=await allowedResponse.json();
    const receipt=allowedJson.result?.structuredContent?.receipt;
    const verification=verifyReceipt({publicPem:receiptKey.publicPem,receipt});
    const replay=(await makeCall(url,f.capability,f.proof)).status;
    const direct=(await fetch(backendBase+'/internal/execute',{method:'POST',headers:{'content-type':'application/json'},body:'{}'})).status;
    const out={version:'0.95.0',kind:'synthetic-local-secure-pilot',checks:{stolen,allowed,replay,direct,receiptVerified:verification.verified,
      backendOperations:durableStore.count(),journalStatus:journal.get(receipt.claims.operationId)?.state},
      limitation:'Same-host local test only. Docker network isolation must be independently checked.'};
    return {...out,success:stolen===403&&allowed===200&&replay===403&&direct===401&&verification.verified&&durableStore.count()===1};
  }finally{if(gateway)await close(gateway);await close(backend);f.close();journal.close();durableStore.close();rmSync(root,{recursive:true,force:true});}
}
