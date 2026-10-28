/** Explicit operator-side, read-only reconciliation of a previously uncertain operation.
 * No tool is invoked and no second execution is attempted.
 */
import {AuthorityError,digest} from './authority.js';
import {verifyReceipt,signReceipt} from './pilot-receipts.js';
import {verifyBackendAttestation} from './backend-attestation.js';
export async function reconcileSyntheticOperation({operationId,journal,backendUrl,backendSecret,backendPublicPem,receiptPrivatePem,receiptPublicPem,fetchFn=fetch,now=()=>Math.floor(Date.now()/1000)}){
  const entry=journal.get(operationId);
  if(!entry||entry.state!=='upstream-uncertain'||!entry.receipt)throw new AuthorityError('operation-not-reconcilable');
  verifyReceipt({publicPem:receiptPublicPem,receipt:entry.receipt,backendPublicPem});
  if(entry.receipt.claims.operationId!==operationId || entry.receipt.claims.requestHash!==entry.argsHash)throw new AuthorityError('journal-scope-mismatch');
  const endpoint=new URL(backendUrl);
  if(endpoint.pathname!=='/internal/execute'||endpoint.search||endpoint.hash||endpoint.username||endpoint.password||!['http:','https:'].includes(endpoint.protocol))throw new AuthorityError('invalid-backend-endpoint');
  endpoint.pathname='/internal/status';
  const response=await fetchFn(endpoint,{method:'POST',redirect:'error',signal:AbortSignal.timeout(3000),headers:{'content-type':'application/json',authorization:`Bearer ${backendSecret}`},body:JSON.stringify({operationId,requestHash:entry.argsHash})});
  if(response.status!==200)throw new AuthorityError('backend-status-not-confirmed');
  const size=Number(response.headers.get('content-length'));
  if(Number.isFinite(size)&&size>8192)throw new AuthorityError('oversized-status-response');
  let buffer=Buffer.alloc(0);
  for await(const chunk of response.body){buffer=Buffer.concat([buffer,Buffer.from(chunk)]);if(buffer.length>8192)throw new AuthorityError('oversized-status-response');}
  let record;try{record=JSON.parse(buffer.toString('utf8'));}catch{throw new AuthorityError('invalid-status-response');}
  if(record.status!=='simulated'||record.operationId!==operationId||record.requestHash!==entry.argsHash)throw new AuthorityError('status-mismatch');
  verifyBackendAttestation({publicPem:backendPublicPem,attestation:record.attestation,operationId,requestHash:entry.argsHash});
  const claims={...entry.receipt.claims,outcome:'simulated',backendAttestation:record.attestation,responseHash:digest(record.attestation),observedAt:now()};
  const receipt=signReceipt({privatePem:receiptPrivatePem,claims});
  verifyReceipt({publicPem:receiptPublicPem,backendPublicPem,receipt});
  journal.reconcile(operationId,receipt);
  return {reconciled:true,receipt,operationId,executionRepeated:false};
}
