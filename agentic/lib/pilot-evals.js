/** 100+ real local MCP JSON-RPC calls with cryptographic adversarial probes.
 * Every tool effect is a fake, isolated SQLite record. Does not claim broad coverage.
 */
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fixture,AGENT,TOOL,RESOURCE,ACTION,ARGS} from './authority-fixture.js';
import {createIntent,createExecution,newIdentity} from './authority.js';
import {ExecutionJournal} from './pilot-receipts.js';
import {DurableSyntheticStore,createDurableSyntheticBackend} from './pilot-backend.js';
import {createSecurePilotGateway} from './pilot-mcp.js';
const PROTOCOL='2026-07-28';
export async function runPilotEvaluations({count=100}={}){
  if(!Number.isSafeInteger(count)||count<1||count>1000)throw Error('Count must be 1–1000');
  const root=mkdtempSync(join(tmpdir(),'faraday-095-evals-'));
  const f=fixture(root),receiptKey=newIdentity(),backendKey=newIdentity(),journal=new ExecutionJournal(join(root,'journal.sqlite'));
  const store=new DurableSyntheticStore(join(root,'backend.sqlite'));
  const backend=createDurableSyntheticBackend({secret:f.backendSecret,store,attestationPrivatePem:backendKey.privatePem});let gateway;
  const close=s=>new Promise(ok=>s.close(ok));const start=s=>new Promise(ok=>s.listen(0,'127.0.0.1',()=>ok(`http://127.0.0.1:${s.address().port}`)));
  const cases=[];
  try{
    const upstream=await start(backend);
    gateway=createSecurePilotGateway({gate:f.gate,backendUrl:upstream+'/internal/execute',backendSecret:f.backendSecret,journal,receiptPrivatePem:receiptKey.privatePem,backendPublicPem:backendKey.publicPem});
    const url=await start(gateway);
    async function call(capability,proof,args=ARGS,sendAuth=true){
      const headers={'content-type':'application/json','mcp-protocol-version':PROTOCOL,'mcp-method':'tools/call','mcp-name':TOOL};
      if(sendAuth){headers['x-faraday-capability']=capability;headers['x-faraday-proof']=Buffer.from(JSON.stringify(proof)).toString('base64url');}
      const req={jsonrpc:'2.0',id:42,method:'tools/call',params:{name:TOOL,arguments:args,_meta:{'io.modelcontextprotocol/protocolVersion':PROTOCOL}}};
      const response=await fetch(url+'/mcp',{method:'POST',headers,body:JSON.stringify(req)});return response.status;
    }
    for(let i=0;i<count;i++){
      const intent=createIntent({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,agentPrivatePem:f.agent.privatePem});
      const cap=f.iss.issue(intent,{ttl:100});
      const signed=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,capability:cap,agentPrivatePem:f.agent.privatePem});
      const kind=['valid','stolen-key','changed-arguments','replay','missing-auth'][i%5];
      let passed=false;
      if(kind==='valid')passed=await call(cap,signed)===200;
      if(kind==='stolen-key'){
        const forged=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,capability:cap,agentPrivatePem:newIdentity().privatePem});
        passed=await call(cap,forged)===403;
      }
      if(kind==='changed-arguments')passed=await call(cap,signed,{...ARGS,amount_cents:15000})===403;
      if(kind==='replay')passed=await call(cap,signed)===200&&await call(cap,signed)===403;
      if(kind==='missing-auth')passed=await call(cap,signed,ARGS,false)===403;
      cases.push({id:`pilot-${String(i+1).padStart(4,'0')}`,kind,passed});
    }
    return {format:'faraday-secure-pilot-evals',version:'0.95.0',kind:'local-synthetic-mcp-jsonrpc',
      summary:{total:count,passed:cases.filter(x=>x.passed).length,failed:cases.filter(x=>!x.passed).length,
        backendOperations:store.count()},cases,
      gaps:['No real OIDC/SVID attestation','Backend evidence is cryptographically signed, but not independently verified physical-world effects','No external MCP conformance matrix',
        'No production sandbox, host protection, or third-party API isolation']};
  }finally{if(gateway)await close(gateway);await close(backend);f.close();journal.close();store.close();rmSync(root,{recursive:true,force:true});}
}
