import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {canonical,digest} from './authority.js';
import {verifyReceipt} from './pilot-receipts.js';

const FORMAT='faraday-evidence-checkpoint/v1';
const DOMAIN=Buffer.from('FARADAY-CHECKPOINT-WITNESS-V1\0');
const fail=code=>{throw Error('evidence-checkpoint:'+code);};
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const validId=value=>typeof value==='string'&&/^[A-Za-z0-9._:-]{3,128}$/.test(value);
function publicKey(value){
  try{const key=createPublicKey(value);if(key.asymmetricKeyType!=='ed25519')fail('invalid-key');return key;}catch{fail('invalid-key');}
}
function separateWitness(witness,gateway,backend){
  const fingerprint=key=>key.export({type:'spki',format:'der'}).toString('base64');
  const witnessFingerprint=fingerprint(witness);
  if([fingerprint(publicKey(gateway)),fingerprint(publicKey(backend))].includes(witnessFingerprint))fail('witness-key-not-independent');
}
function receiptChain(receipts,gatewayPublicPem,backendPublicPem,trustedPrefix=null){
  if(!Array.isArray(receipts)||receipts.length<1||receipts.length>1000)fail('invalid-length');
  if(trustedPrefix!==null&&(!exact(trustedPrefix,['count','root'])||!Number.isSafeInteger(trustedPrefix.count)||trustedPrefix.count<1||trustedPrefix.count>receipts.length||typeof trustedPrefix.root!=='string'))fail('invalid-prefix');
  const seen=new Set();let root='GENESIS';
  for(const [index,receipt] of receipts.entries()){
    let result;try{result=verifyReceipt({publicPem:gatewayPublicPem,backendPublicPem,receipt});}catch{fail('invalid-receipt');}
    if(typeof result.operationId!=='string'||!/^[-_A-Za-z0-9]{20,128}$/.test(result.operationId)||seen.has(result.operationId))fail('duplicate-or-invalid-operation');
    seen.add(result.operationId);
    root=digest({format:FORMAT,index,previous:root,receiptDigest:digest(receipt)});
    if(trustedPrefix?.count===index+1&&trustedPrefix.root!==root)fail('prefix-mismatch');
  }
  return root;
}
const body=claims=>Buffer.concat([DOMAIN,canonical(claims)]);
export function witnessEvidenceCheckpoint(options){
  if(options?.checkpoint!==undefined)return witnessLegacyEvidenceCheckpoint(options);
  const {receipts,gatewayPublicPem,backendPublicPem,witnessPrivatePem,witnessId,issuedAt=Date.now()}=options;
  if(!validId(witnessId)||!Number.isSafeInteger(issuedAt)||issuedAt<1)fail('invalid-witness');
  let key;try{key=createPrivateKey(witnessPrivatePem);if(key.asymmetricKeyType!=='ed25519')fail('invalid-key');}catch{fail('invalid-key');}
  separateWitness(createPublicKey(key),gatewayPublicPem,backendPublicPem);
  const root=receiptChain(receipts,gatewayPublicPem,backendPublicPem);
  const claims={format:FORMAT,count:receipts.length,root,witnessId,issuedAt};
  return {claims,receipts,signature:sign(null,body(claims),key).toString('base64url')};
}
export function verifyEvidenceCheckpoint({checkpoint,gatewayPublicPem,backendPublicPem,witnessPublicPem,expectedWitnessId,trustedPrefix=null}){
  if(!exact(checkpoint,['claims','receipts','signature'])||!exact(checkpoint.claims,['format','count','root','witnessId','issuedAt']))fail('invalid-checkpoint');
  const {claims,receipts,signature}=checkpoint;
  if(claims.format!==FORMAT||!validId(expectedWitnessId)||claims.witnessId!==expectedWitnessId||!Number.isSafeInteger(claims.count)||claims.count<1||!Number.isSafeInteger(claims.issuedAt)||claims.issuedAt<1||typeof signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signature)||Buffer.from(signature,'base64url').toString('base64url')!==signature)fail('invalid-checkpoint');
  const key=publicKey(witnessPublicPem);separateWitness(key,gatewayPublicPem,backendPublicPem);
  let valid=false;try{valid=verify(null,body(claims),key,Buffer.from(signature,'base64url'));}catch{}
  if(!valid)fail('invalid-signature');
  const root=receiptChain(receipts,gatewayPublicPem,backendPublicPem,trustedPrefix);
  if(claims.root!==root||claims.count!==receipts.length)fail('chain-mismatch');
  return {verified:true,root,count:receipts.length,witnessId:claims.witnessId};
}
const sha=value=>createHash('sha256').update(Buffer.isBuffer(value)?value:canonical(value)).digest('hex');
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
function legacyBody({checkpoint,witnessId,issuedAt}){
 return Buffer.concat([Buffer.from('FARADAY-CHECKPOINT-WITNESS-V1\0'),canonical({format:FORMAT,root:checkpoint.summary.root,count:checkpoint.summary.count,witnessId,issuedAt})]);
}
function witnessLegacyEvidenceCheckpoint({checkpoint,witnessPrivatePem,witnessId,issuedAt=Date.now()}){
 if(!checkpoint||checkpoint.format!==FORMAT||!assertString(witnessId)||!Number.isSafeInteger(issuedAt)||issuedAt<1||!witnessPrivatePem)fail('invalid-witness-input');
 const signature=sign(null,legacyBody({checkpoint,witnessId,issuedAt}),createPrivateKey(witnessPrivatePem)).toString('base64url');
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
 try{const key=publicKey(witnessPublicPem);separateWitness(key,gatewayPublicPem,backendPublicPem);valid=verify(null,legacyBody({checkpoint,witnessId:witness.id,issuedAt:witness.issuedAt}),key,Buffer.from(witness.signature,'base64url'));}catch{}
 if(!valid)fail('invalid-witness-signature');
 return {verified:true,witnessId:witness.id,count:checkpoint.receipts.length,root};
}
