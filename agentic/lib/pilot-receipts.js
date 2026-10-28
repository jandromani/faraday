/** FARADAY Secure Pilot: independent verifier for gateway-attested observations.
 * Receipts attest what the GATEWAY observed, NOT independently verified business effects.
 */
import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,lstatSync,chmodSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {canonical,AuthorityError,digest} from './authority.js';
const PREFIX=Buffer.from('FARADAY-RECEIPT-V095\0');
const b64=(b)=>Buffer.from(b).toString('base64url');
const unsigned=(body)=>Buffer.concat([PREFIX,canonical(body)]);
export function signReceipt({privatePem,claims}){
  const fields=['version','operationId','agent','tool','resource','action','argsHash','rule','outcome','responseHash','observedAt'];
  if(!claims||Object.keys(claims).sort().join('|')!==fields.sort().join('|')||claims.version!==1||
     !['simulated','upstream-uncertain','upstream-rejected'].includes(claims.outcome))throw new AuthorityError('invalid-receipt');
  return {claims,signature:b64(sign(null,unsigned(claims),createPrivateKey(privatePem)))};
}
export function verifyReceipt({publicPem,receipt}){
  if(!receipt||typeof receipt!=='object'||Object.keys(receipt).sort().join('|')!=='claims|signature')throw new AuthorityError('invalid-receipt');
  const {claims,signature}=receipt;
  if(!claims||claims.version!==1||!['simulated','upstream-uncertain','upstream-rejected'].includes(claims.outcome))throw new AuthorityError('invalid-receipt');
  if(typeof signature!=='string'||!/^[A-Za-z0-9_-]+$/.test(signature)||signature.length>200)throw new AuthorityError('invalid-receipt');
  let ok=false;try{ok=verify(null,unsigned(claims),createPublicKey(publicPem),Buffer.from(signature,'base64url'));}catch{throw new AuthorityError('invalid-receipt-signature');}
  if(!ok)throw new AuthorityError('invalid-receipt-signature');
  return {verified:true,outcome:claims.outcome,operationId:claims.operationId,
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
      receipt_json TEXT, created_at INTEGER NOT NULL);`);
    if(process.platform!=='win32')chmodSync(path,0o600);
    this.insert=this.db.prepare('INSERT INTO executions (operation_id,args_hash,state,created_at) VALUES (?,?,?,?)');
    this.update=this.db.prepare('UPDATE executions SET state=?,receipt_json=? WHERE operation_id=? AND state=\'reserved\'');
    this.getStatement=this.db.prepare('SELECT operation_id,args_hash,state,receipt_json FROM executions WHERE operation_id=?');
  }
  reserve(id,argsHash){
    if(typeof id!=='string'||id.length>128||typeof argsHash!=='string'||argsHash.length>100)throw new AuthorityError('invalid-operation');
    try{this.insert.run(id,argsHash,'reserved',Date.now());}
    catch{throw new AuthorityError('operation-already-reserved-or-storage-unavailable');}
  }
  finish(id,state,receipt){
    if(!['simulated','upstream-uncertain','upstream-rejected'].includes(state))throw new AuthorityError('invalid-state');
    try{if(this.update.run(state,JSON.stringify(receipt),id).changes!==1)throw new Error('not-reserved');}
    catch{throw new AuthorityError('journal-finalize-failed');}
  }
  get(id){const r=this.getStatement.get(id);return r?{operationId:r.operation_id,argsHash:r.args_hash,state:r.state,receipt:r.receipt_json?JSON.parse(r.receipt_json):null}:null;}
  close(){this.db.close();}
}
