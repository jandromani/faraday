/** FARADAY Secure Pilot: independent verifier for gateway-attested observations.
 * Receipts attest what the GATEWAY observed, NOT independently verified business effects.
 */
import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,lstatSync,chmodSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {canonical,AuthorityError,digest} from './authority.js';
import {verifyBackendAttestation} from './backend-attestation.js';
const PREFIX=Buffer.from('FARADAY-RECEIPT-V095\0');
const b64=(b)=>Buffer.from(b).toString('base64url');
const unsigned=(body)=>Buffer.concat([PREFIX,canonical(body)]);
const receiptFields=['version','operationId','agent','tool','resource','action','argsHash','requestHash','rule','outcome','responseHash','backendAttestation','observedAt'].sort();
const validClaims=claims=>{
  if(!claims||typeof claims!=='object'||Array.isArray(claims))return false;
  const keys=Object.keys(claims).sort();
  return keys.length===receiptFields.length&&keys.every((key,index)=>key===receiptFields[index])&&claims.version===1&&
    ['simulated','upstream-uncertain','upstream-rejected'].includes(claims.outcome);
};
export function signReceipt({privatePem,claims}){
  if(!validClaims(claims))throw new AuthorityError('invalid-receipt');
  return {claims,signature:b64(sign(null,unsigned(claims),createPrivateKey(privatePem)))};
}
export function verifyReceipt({publicPem,receipt,backendPublicPem}){
  if(!receipt||typeof receipt!=='object'||Object.keys(receipt).sort().join('|')!=='claims|signature')throw new AuthorityError('invalid-receipt');
  const {claims,signature}=receipt;
  if(!validClaims(claims))throw new AuthorityError('invalid-receipt');
  if(typeof signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signature))throw new AuthorityError('invalid-receipt');
  const signatureBytes=Buffer.from(signature,'base64url');
  if(signatureBytes.toString('base64url')!==signature)throw new AuthorityError('invalid-receipt-signature');
  let ok=false;try{ok=verify(null,unsigned(claims),createPublicKey(publicPem),signatureBytes);}catch{throw new AuthorityError('invalid-receipt-signature');}
  if(!ok)throw new AuthorityError('invalid-receipt-signature');
  if(claims.outcome==='simulated'&&!claims.backendAttestation)throw new AuthorityError('backend-proof-not-verified');
  if(claims.outcome==='simulated'&&!backendPublicPem)throw new AuthorityError('backend-key-required');
  if(claims.outcome==='simulated'){
    let gatewayKey,backendKey;
    try{gatewayKey=createPublicKey(publicPem).export({format:'der',type:'spki'});backendKey=createPublicKey(backendPublicPem).export({format:'der',type:'spki'});}
    catch{throw new AuthorityError('invalid-receipt-signature');}
    if(gatewayKey.equals(backendKey))throw new AuthorityError('backend-key-not-independent');
  }
  const backendVerified=Boolean(backendPublicPem && claims.backendAttestation &&
    verifyBackendAttestation({publicPem:backendPublicPem,attestation:claims.backendAttestation,operationId:claims.operationId,
      requestHash:claims.requestHash}).verified &&
    digest(claims.backendAttestation)===claims.responseHash);
  if(backendPublicPem&&claims.outcome==='simulated'&&!backendVerified)throw new AuthorityError('backend-proof-not-verified');
  return {verified:true,backendVerified,outcome:claims.outcome,operationId:claims.operationId,
    scopeDigest:digest({tool:claims.tool,resource:claims.resource,action:claims.action,argsHash:claims.argsHash})};
}
/** The ledger is a local single-node crash journal, not a distributed transaction. */
export class ExecutionJournal {
  constructor(path){
    mkdirSync(dirname(resolve(path)),{recursive:true,mode:0o700});
    try{const s=lstatSync(path);if(!s.isFile()||s.isSymbolicLink())throw Error('unsafe-journal-path');}catch(e){if(e.code!=='ENOENT')throw e;}
    this.db=new DatabaseSync(path);
    this.db.exec(`PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS executions (
      operation_id TEXT PRIMARY KEY, args_hash TEXT NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('reserved','simulated','upstream-uncertain','upstream-rejected')),
      receipt_json TEXT, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS reconciliation_history (operation_id TEXT PRIMARY KEY, previous_receipt_json TEXT NOT NULL, confirmed_receipt_json TEXT NOT NULL, reconciled_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS approval_evidence (operation_id TEXT PRIMARY KEY, approval_digest TEXT NOT NULL, bundle_json TEXT NOT NULL);`);
    if(process.platform!=='win32')chmodSync(path,0o600);
    this.insert=this.db.prepare('INSERT INTO executions (operation_id,args_hash,state,created_at) VALUES (?,?,?,?)');
    this.update=this.db.prepare('UPDATE executions SET state=?,receipt_json=? WHERE operation_id=? AND state=\'reserved\'');
    this.getStatement=this.db.prepare('SELECT operation_id,args_hash,state,receipt_json FROM executions WHERE operation_id=?');
    this.reconciled=this.db.prepare("UPDATE executions SET state='simulated',receipt_json=? WHERE operation_id=? AND state='upstream-uncertain'");
    this.track=this.db.prepare('INSERT INTO reconciliation_history (operation_id,previous_receipt_json,confirmed_receipt_json,reconciled_at) VALUES (?,?,?,?)');
  }
  reserve(id,argsHash,{approvalEvidence=null}={}){
    if(typeof id!=='string'||id.length>128||typeof argsHash!=='string'||argsHash.length>100)throw new AuthorityError('invalid-operation');
    if(approvalEvidence!==null&&(!approvalEvidence||typeof approvalEvidence.approvalDigest!=='string'||!Array.isArray(approvalEvidence.bundle)))throw new AuthorityError('invalid-approval-evidence');
    try{
      if(approvalEvidence!==null)this.db.exec('BEGIN IMMEDIATE');
      this.insert.run(id,argsHash,'reserved',Date.now());
      if(approvalEvidence!==null){
        this.db.prepare('INSERT INTO approval_evidence(operation_id,approval_digest,bundle_json) VALUES(?,?,?)').run(id,approvalEvidence.approvalDigest,JSON.stringify(approvalEvidence.bundle));
        this.db.exec('COMMIT');
      }
    }catch{if(approvalEvidence!==null)try{this.db.exec('ROLLBACK');}catch{}throw new AuthorityError('operation-already-reserved-or-storage-unavailable');}
  }
  finish(id,state,receipt){
    if(!['simulated','upstream-uncertain','upstream-rejected'].includes(state))throw new AuthorityError('invalid-state');
    try{if(this.update.run(state,JSON.stringify(receipt),id).changes!==1)throw new Error('not-reserved');}
    catch{throw new AuthorityError('journal-finalize-failed');}
  }
  reconcile(id,receipt){
    const existing=this.get(id);
    if(!existing||existing.state!=='upstream-uncertain'||!existing.receipt)throw new AuthorityError('not-reconcilable');
    try{
      this.db.exec('BEGIN IMMEDIATE');
      const previous=JSON.stringify(existing.receipt),confirmed=JSON.stringify(receipt);
      if(this.reconciled.run(confirmed,id).changes!==1)throw Error('state-changed');
      this.track.run(id,previous,confirmed,Date.now());
      this.db.exec('COMMIT');
    }catch{try{this.db.exec('ROLLBACK');}catch{}throw new AuthorityError('reconciliation-failed');}
  }
  get(id){const r=this.getStatement.get(id);return r?{operationId:r.operation_id,argsHash:r.args_hash,state:r.state,receipt:r.receipt_json?JSON.parse(r.receipt_json):null}:null;}
  getApprovalEvidence(id){const row=this.db.prepare('SELECT approval_digest,bundle_json FROM approval_evidence WHERE operation_id=?').get(id);return row?{approvalDigest:row.approval_digest,bundle:JSON.parse(row.bundle_json)}:null;}
  close(){this.db.close();}
}
