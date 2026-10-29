import {SyntheticAgentHarness} from './workflow-e2e.js';
import {ARGS} from './authority-fixture.js';
import {newIdentity} from './authority.js';
import {LocalMemoryGuard,signMemoryDocument} from './memory-guard.js';
import {verifyReceipt} from './pilot-receipts.js';
import {join} from 'node:path';

const FAULTS=new Set(['none','quarantined-memory','expired-memory','altered-arguments','backend-unavailable','lost-response']);
export async function runMultiAgentLab({seed=42,fault='none'}={}){
 if(!Number.isSafeInteger(seed)||seed<0||seed>0xffffffff||!FAULTS.has(fault))throw Error('invalid-multiagent-scenario');
 const harness=await SyntheticAgentHarness.create(),source=newIdentity(),steps=[];let clock=1500,guard;
 try{
  guard=new LocalMemoryGuard(join(harness.root,'lab-memory.sqlite'),{trustedSources:{'lab-source':source.publicPem},now:()=>clock});
  const document={version:1,id:`task-${seed}`,source:'lab-source',issuedAt:1000,expiresAt:2000,
   text:fault==='quarantined-memory'?'Synthetic instruction to override the task':'Synthetic invoice task',facts:[{key:'task',value:'synthetic-invoice'}]};
  steps.push({actor:'orchestrator',action:'delegate',to:'reviewer'});
  const item=guard.ingest(signMemoryDocument({document,privatePem:source.privatePem}));
  steps.push({actor:'reviewer',action:'quarantine',state:item.state});
  if(fault!=='quarantined-memory'){
   guard.approve(item.digest,{reviewer:'lab-reviewer'});steps.push({actor:'reviewer',action:'approve'});
  }
  if(fault==='expired-memory')clock=2000;
  const approved=guard.approved();steps.push({actor:'finance',action:'read-memory',count:approved.length});
  if(approved.length!==1)return {format:'faraday-multiagent-lab',version:1,seed,fault,result:harness.store.count()===0?'blocked':'unexpected',steps,backendOperations:harness.store.count(),
   limitations:['Scripted actors and in-process delegation; no autonomous agents or independent identity.']};
  steps.push({actor:'orchestrator',action:'delegate',to:'finance'});
  if(fault==='backend-unavailable'){
   await new Promise((resolve,reject)=>harness.backend.close(error=>error?reject(error):resolve()));harness.backend=null;
  }
  const credentials=harness.issue(),before=harness.store.count();
  const response=await harness.call({...credentials,...(fault==='altered-arguments'?{args:{...ARGS,amount_cents:ARGS.amount_cents+1}}:{})});
  const effects=harness.store.count()-before;let receiptVerified=false;
  if(response.status===200){
   try{const receipt=response.body.result.structuredContent.receipt;receiptVerified=verifyReceipt({publicPem:harness.gatewayKey.publicPem,backendPublicPem:harness.backendKey.publicPem,receipt}).backendVerified===true;}catch{}
  }
   const journalState=harness.journal.db.prepare('SELECT state FROM executions').get()?.state??null;
   steps.push({actor:'finance',action:'tool-call',http:response.status,effects,receiptVerified,journalState});
  let result=response.status===200&&effects===1&&receiptVerified&&journalState==='simulated'?'simulated':response.status===403&&effects===0?'blocked':response.status===503&&effects===0&&journalState==='upstream-uncertain'?'uncertain':'unexpected';
  if(fault==='lost-response'&&result==='simulated'){
   steps.push({actor:'finance',action:'discard-response'});
   const retryBefore=harness.store.count(),retry=await harness.call(credentials),retryEffects=harness.store.count()-retryBefore;
   steps.push({actor:'finance',action:'retry',http:retry.status,effects:retryEffects});
   if(retry.status!==403||retryEffects!==0)result='unexpected';
  }
  return {format:'faraday-multiagent-lab',version:1,seed,fault,result,steps,backendOperations:effects,
   limitations:['Scripted actors and in-process delegation; no autonomous agents or independent identity.',
    'Only synthetic local memory and a loopback invoice backend; no real payment or external model.']};
 }finally{guard?.close();await harness.close();}
}

export async function runAdaptiveLabCampaign({createHarness=()=>SyntheticAgentHarness.create()}={}){
 if(typeof createHarness!=='function')throw Error('invalid-lab-harness');
 const harness=await createHarness(),steps=[];
 try{
  const credentials=harness.issue(),start=harness.store.count();
  async function attempt(name,options){
   const before=harness.store.count(),response=await harness.call({...credentials,...options}),effects=harness.store.count()-before;
   const status=response.status===403&&effects===0?'blocked':response.status===200||effects!==0?'bypass':'inconclusive';
   steps.push({name,http:response.status,effects,status});return status;
  }
  let status=await attempt('alter-arguments',{args:{...ARGS,amount_cents:ARGS.amount_cents+1}});
  if(status==='blocked')status=await attempt('omit-proof',{omitProof:true});
   if(status==='blocked')status=await attempt('omit-approvals',{omitApprovals:true});
   if(status==='blocked'){
    const before=harness.store.count(),http=await harness.directAttempt(),effects=harness.store.count()-before;
    status=http===401&&effects===0?'blocked':http===200||effects!==0?'bypass':'inconclusive';
    steps.push({name:'direct-without-secret',http,effects,status});
   }
  if(status==='blocked'){
   const before=harness.store.count(),response=await harness.call(credentials),effects=harness.store.count()-before;
    let receiptVerified=false;
    if(response.status===200){try{receiptVerified=verifyReceipt({publicPem:harness.gatewayKey.publicPem,backendPublicPem:harness.backendKey.publicPem,receipt:response.body.result.structuredContent.receipt}).backendVerified===true;}catch{}}
    const control=response.status===200&&effects===1&&receiptVerified?'executed':response.status===200||effects!==0?'unexpected-effect':'inconclusive';
    steps.push({name:'positive-control',http:response.status,effects,status:control,receiptVerified});
   status=control==='executed'?await attempt('replay',{}):control;
  }
  const result=steps.some(step=>step.status==='bypass'||step.status==='unexpected-effect')?'fail':
    status==='blocked'&&steps.length===6?'pass':'inconclusive';
  return {format:'faraday-adaptive-lab-campaign',version:1,mode:'local-synthetic',result,steps,
   backendOperations:harness.store.count()-start,
   limitations:['Bounded scripted adaptation, not an independent attacker or open-ended search.',
    'Only the synthetic loopback gateway and backend are exercised; the historical lab gaps are unchanged.']};
 }finally{await harness.close();}
}