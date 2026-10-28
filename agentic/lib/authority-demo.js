import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fixture} from './authority-fixture.js';
import {createAuthorityGateway,createSyntheticBackend} from './authority-gateway.js';
import {newIdentity,createExecution,createIntent,AuthorityError} from './authority.js';
import {AGENT,TOOL,RESOURCE,ACTION,ARGS} from './authority-fixture.js';
export async function runAuthorityDemo(){
  const dir=mkdtempSync(join(tmpdir(),'faraday-authority-'));
  const f=fixture(dir);const backend=createSyntheticBackend({secret:f.backendSecret});
  await new Promise(resolve=>backend.listen(0,'127.0.0.1',resolve));
  const gateway=createAuthorityGateway({gate:f.gate,backendUrl:`http://127.0.0.1:${backend.address().port}/internal/execute`,backendSecret:f.backendSecret});
  await new Promise(resolve=>gateway.listen(0,'127.0.0.1',resolve));
  const addr=`http://127.0.0.1:${gateway.address().port}/execute`;
  const request=(capability,proof)=>fetch(addr,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({capability,proof})});
  try{
    const attacker=newIdentity();
    const fake=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,capability:f.capability,agentPrivatePem:attacker.privatePem});
    const stolen=await request(f.capability,fake);
    const allowed=await request(f.capability,f.proof);
    const replay=await request(f.capability,f.proof);
    const direct=await fetch(`http://127.0.0.1:${backend.address().port}/internal/execute`,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
    const success=stolen.status===403&&allowed.status===200&&replay.status===403&&direct.status===401;
    return {kind:'synthetic-local',success,checks:{stolenCapability:stolen.status,allowed:allowed.status,replay:replay.status,directBackendWithoutServiceCredential:direct.status},
      limitation:'Same-host local demo does not prove network no-bypass. Run docker isolated demo to test network separation.'};
  }finally{
    await Promise.all([new Promise(resolve=>gateway.close(resolve)),new Promise(resolve=>backend.close(resolve))]);
    f.close();rmSync(dir,{recursive:true,force:true});
  }
}
/** Live Ed25519 evaluations with a real transactional SQLite ledger.
 * Outcomes are recorded without exposing capabilities or private keys.
 */
export function runAuthorityEvaluations({count=100}={}) {
  if(!Number.isSafeInteger(count)||count<1||count>1000)throw Error('Invalid evaluation count');
  const root=mkdtempSync(join(tmpdir(),'faraday-v09-eval-'));
  const f=fixture(root);const results=[];
  try {
    for(let n=0;n<count;n++){
      const variant=n%5;let passed=false,check='';
      try {
        const freshIntent=createIntent({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,agentPrivatePem:f.agent.privatePem});
        const cap=f.iss.issue(freshIntent);
        const legitimate=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,capability:cap,agentPrivatePem:f.agent.privatePem});
        if(variant===0){check='legitimate';passed=Boolean(f.gate.authorize({capability:cap,proof:legitimate}));}
        else if(variant===1){check='stolen-token';const rogue=newIdentity();const bad=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,capability:cap,agentPrivatePem:rogue.privatePem});try{f.gate.authorize({capability:cap,proof:bad});}catch(e){passed=e instanceof AuthorityError&&e.code==='invalid-signature';}}
        else if(variant===2){check='scope-substitution';const bad=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:{...ARGS,amount_cents:12000},capability:cap,agentPrivatePem:f.agent.privatePem});try{f.gate.authorize({capability:cap,proof:bad});}catch(e){passed=e instanceof AuthorityError&&e.code==='scope-mismatch';}}
        else if(variant===3){check='replay';f.gate.authorize({capability:cap,proof:legitimate});try{f.gate.authorize({capability:cap,proof:legitimate});}catch(e){passed=e instanceof AuthorityError&&e.code==='capability-replayed-or-ledger-unavailable';}}
        else {check='policy-restriction';try{f.iss.issue(createIntent({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:{...ARGS,amount_cents:50000},agentPrivatePem:f.agent.privatePem}));}catch(e){passed=e instanceof AuthorityError&&e.code==='policy-denied';}}
      }catch{passed=false;}
      results.push({id:'authority-'+String(n+1).padStart(4,'0'),check,pass:passed});
    }
    const passed=results.filter(x=>x.pass).length;
    return {format:'faraday-authority-evals',version:'0.9.0',mode:'synthetic-cryptographic',
      summary:{total:count,passed,failed:count-passed},cases:results,
      limitation:'Not real SPIFFE/OIDC attestation, not external independent agent penetration testing.'};
  }finally{f.close();rmSync(root,{recursive:true,force:true});}
}
