/** Offline, metadata-only evidence for the synthetic E2E MCP workflow.
 * Hash chaining detects modification without providing provenance of an entire trace.
 * Signed gateway and backend receipts independently authenticate successful operations.
 */
import {createHash} from 'node:crypto';
import {readFileSync,lstatSync} from 'node:fs';
import {verifyReceipt} from './pilot-receipts.js';
const PREFIX='FARADAY-WORKFLOW-V099:';
const hash=obj=>createHash('sha256').update(PREFIX+JSON.stringify(obj)).digest('hex');
const eventTypes=new Set(['model-decision','policy-denied','mcp-denied','mcp-allowed','replay-denied','direct-denied']);
function plain(x){return x!==null&&typeof x==='object'&&!Array.isArray(x);}
export class WorkflowTrace {
  constructor({gatewayPublicPem,backendPublicPem,mode='offline-dummy'}={}){
    if(!gatewayPublicPem||!backendPublicPem||!['offline-dummy','free-model'].includes(mode))throw Error('Invalid workflow trace configuration');
    this.trace={format:'faraday-workflow-evidence',version:1,mode,gatewayPublicPem,backendPublicPem,steps:[],head:'0'.repeat(64),note:'Synthetic MCP workflow; replay is verification-only, no remote calls or side effects.'};
  }
  append(type,{status,modelDecisionHash=null,receipt=null}={}){
    if(!eventTypes.has(type)||typeof status!=='number'||![200,400,401,403,429,503].includes(status)||
      (modelDecisionHash!==null&&!/^[a-f0-9]{64}$/.test(modelDecisionHash))||this.trace.steps.length>=128)throw Error('Invalid workflow trace event');
    const event={type,status,modelDecisionHash,receipt};
    const step={index:this.trace.steps.length,previous:this.trace.head,event,hash:hash({index:this.trace.steps.length,previous:this.trace.head,event})};
    this.trace.steps.push(step);this.trace.head=step.hash;return step;
  }
  result(){return structuredClone(this.trace);}
}
export function verifyWorkflowTrace(trace){
  if(!plain(trace)||trace.format!=='faraday-workflow-evidence'||trace.version!==1||
    !['offline-dummy','free-model'].includes(trace.mode)||!Array.isArray(trace.steps)||trace.steps.length>128||
    typeof trace.gatewayPublicPem!=='string'||typeof trace.backendPublicPem!=='string')throw Error('Invalid workflow trace');
  let prev='0'.repeat(64),receipts=0,authenticated=0;
  for(const [index,step] of trace.steps.entries()){
    if(!plain(step)||step.index!==index||step.previous!==prev||!plain(step.event)||!eventTypes.has(step.event.type)||
      typeof step.event.status!=='number'||(step.event.modelDecisionHash!==null&&!/^[a-f0-9]{64}$/.test(step.event.modelDecisionHash))||
      step.hash!==hash({index,previous:prev,event:step.event}))throw Error('Workflow trace integrity failed');
    if(step.event.receipt!==null){
      if(step.event.type!=='mcp-allowed'||step.event.status!==200)throw Error('Receipt attached to non-success');
      const result=verifyReceipt({publicPem:trace.gatewayPublicPem,backendPublicPem:trace.backendPublicPem,receipt:step.event.receipt});
      if(!result.verified||!result.backendVerified||result.outcome!=='simulated')throw Error('Invalid backend or gateway receipt');
      authenticated++;receipts++;
    }
    if(step.event.type==='mcp-allowed'&&(!step.event.receipt||step.event.status!==200))throw Error('Successful MCP operation lacks signed receipts');
    prev=step.hash;
  }
  if(prev!==trace.head)throw Error('Workflow trace head mismatch');
  return {verified:true,events:trace.steps.length,signedBackendOperations:receipts,authenticatedReceipts:authenticated,mode:trace.mode,
    limitation:'Trace chain is not independently signed; backend and gateway receipts authenticate only their scoped synthetic operations.'};
}
export function readWorkflowTrace(file){
  const st=lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||st.size>1024*1024)throw Error('Unsafe trace file');
  const x=JSON.parse(readFileSync(file,'utf8'));verifyWorkflowTrace(x);return x;
}
export function modelDecisionHash(text){if(typeof text!=='string'||text.length>12_000)throw Error('Invalid model response');return createHash('sha256').update(text).digest('hex');}
