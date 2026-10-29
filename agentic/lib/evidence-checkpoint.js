/** Offline evidence checkpoint. Receipts are verified, chained and signed by a
 * separately provisioned witness key. The caller must arrange external custody
 * of that key and checkpoint; generating a key in the same gateway is not independence.
 */
import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {verifyReceipt} from './pilot-receipts.js';
import {canonical} from './authority.js';
const FORMAT='faraday-evidence-checkpoint/v1';
const sha=value=>createHash('sha256').update(Buffer.isBuffer(value)?value:canonical(value)).digest('hex');
function fail(code){throw Error('evidence-checkpoint:'+code);}
function assertString(value){return typeof value==='string'&&/^[A-Za-z0-9._:-]{3,128}$/.test(value);}
function strictSignature(v){return typeof v==='string'&&/^[A-Za-z0-9_-]{86}$/.test(v)&&Buffer.from(v,'base64url').toString('base64url')===v;}
function chain(receipts,{gatewayPublicPem,backendPublicPem}){
 if(!Array.isArray(receipts)||!receipts.length||receipts.length>1000)fail('invalid-length');
 if(!gatewayPublicPem||!backendPublicPem)fail('verification-keys-required');
 const seen=new Set();let root='GENESIS';
 for(let i=0;i<receipts.length;i++){
   const r=receipts[i];
   let result;try{result=verifyReceipt({publicPem:gatewayPublicPem,backendPublicPem,receipt:r});}catch{fail('invalid-receipt');}
   if(!assertString(result.operationId)||seen.has(result.operationId))fail('duplicate-or-invalid-operation');
   seen.add(result.operationId);
   root=sha({domain:FORMAT,index:i,previous:root,receiptDigest:sha(r)});
 }
 return root;
}
export function createEvidenceCheckpoint({receipts,gatewayPublicPem,backendPublicPem}){
 const root=chain(receipts,{gatewayPublicPem,backendPublicPem});
 return {format:FORMAT,receipts,summary:{count:receipts.length,root}};
}
function body({checkpoint,witnessId,issuedAt}){
 return Buffer.concat([Buffer.from('FARADAY-CHECKPOINT-WITNESS-V1\0'),canonical({format:FORMAT,root:checkpoint.summary.root,count:checkpoint.summary.count,witnessId,issuedAt})]);
}
export function witnessEvidenceCheckpoint({checkpoint,witnessPrivatePem,witnessId,issuedAt=Date.now()}){
 if(!checkpoint||checkpoint.format!==FORMAT||!assertString(witnessId)||!Number.isSafeInteger(issuedAt)||issuedAt<1||!witnessPrivatePem)fail('invalid-witness-input');
 const signature=sign(null,body({checkpoint,witnessId,issuedAt}),createPrivateKey(witnessPrivatePem)).toString('base64url');
 return {checkpoint,witness:{id:witnessId,issuedAt,signature}};
}
export function verifyWitnessedEvidence({attested,gatewayPublicPem,backendPublicPem,witnessPublicPem,expectedWitnessId,expectedRoot=null,minimumCount=null}){
 if(!attested||!attested.checkpoint||!attested.witness||!witnessPublicPem||!assertString(expectedWitnessId))fail('invalid-input');
 const {checkpoint,witness}=attested;
 if(checkpoint.format!==FORMAT||Object.keys(checkpoint).sort().join('|')!=='format|receipts|summary'||
    Object.keys(witness).sort().join('|')!=='id|issuedAt|signature'||
    witness.id!==expectedWitnessId||!Number.isSafeInteger(witness.issuedAt)||witness.issuedAt<1||!strictSignature(witness.signature))fail('invalid-checkpoint');
 const root=chain(checkpoint.receipts,{gatewayPublicPem,backendPublicPem});
 if(checkpoint.summary?.root!==root||checkpoint.summary?.count!==checkpoint.receipts.length||Object.keys(checkpoint.summary).sort().join('|')!=='count|root')fail('chain-mismatch');
 if(expectedRoot!==null && root!==expectedRoot)fail('stale-checkpoint');
 if(minimumCount!==null && (!Number.isSafeInteger(minimumCount)||checkpoint.receipts.length<minimumCount))fail('stale-checkpoint');
 let valid=false;
 try{valid=verify(null,body({checkpoint,witnessId:witness.id,issuedAt:witness.issuedAt}),createPublicKey(witnessPublicPem),Buffer.from(witness.signature,'base64url'));}catch{}
 if(!valid)fail('invalid-witness-signature');
 return {verified:true,witnessId:witness.id,count:checkpoint.receipts.length,root};
}
