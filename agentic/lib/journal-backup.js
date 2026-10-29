/** E16: signed, operator-driven journal snapshots; never retries external side effects.
 * Not HA, not encrypted backup infrastructure, not independent attestation.
 */
import {backup,DatabaseSync} from 'node:sqlite';
import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {constants,chmodSync,copyFileSync,existsSync,lstatSync,mkdtempSync,mkdirSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {dirname,join,resolve} from 'node:path';
const PREFIX=Buffer.from('FARADAY-JOURNAL-BACKUP-V1\0');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const encode=value=>Buffer.from(JSON.stringify(value));
function safeFile(file,max=100*1024*1024){
 const path=resolve(file);let s;
 try{s=lstatSync(path);}catch{throw Error('backup-file-not-found');}
 if(!s.isFile()||s.isSymbolicLink()||s.size<100||s.size>max)throw Error('unsafe-backup-file');
 return path;
}
function inspect(file){
 const db=new DatabaseSync(file,{readOnly:true});
 try{
  const integrity=db.prepare('PRAGMA integrity_check').get();
  if(!integrity||Object.values(integrity)[0]!=='ok')throw Error('sqlite-integrity-failed');
  const tables=db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('executions','reconciliation_history')").all().map(x=>x.name);
  if(!tables.includes('executions')||!tables.includes('reconciliation_history'))throw Error('unexpected-journal-schema');
  const count=db.prepare('SELECT COUNT(*) AS n FROM executions').get().n;
  if(!Number.isSafeInteger(count)||count<0||count>10000000)throw Error('invalid-journal-count');
  return {operationCount:count};
 }finally{db.close();}
}
function checkSignature(payload,pub){
 if(!payload||Object.keys(payload).sort().join(',')!=='manifest,signature')throw Error('invalid-backup-manifest');
 const {manifest,signature}=payload;
 if(!manifest||manifest.format!=='faraday-journal-backup'||manifest.version!==1||
  Object.keys(manifest).sort().join(',')!=='backupSha256,createdAt,format,operationCount,version'||
  !/^[a-f0-9]{64}$/.test(manifest.backupSha256)||
  !Number.isSafeInteger(manifest.createdAt)||manifest.createdAt<0||
  !Number.isSafeInteger(manifest.operationCount)||manifest.operationCount<0||
  typeof signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signature)||
  Buffer.from(signature,'base64url').toString('base64url')!==signature)throw Error('invalid-backup-manifest');
 let ok=false;
 try{ok=verify(null,Buffer.concat([PREFIX,encode(manifest)]),createPublicKey(pub),Buffer.from(signature,'base64url'));}
 catch{throw Error('invalid-backup-signature');}
 if(!ok)throw Error('invalid-backup-signature');
 return manifest;
}
export async function createSignedJournalBackup({journalPath,backupPath,privatePem,now=()=>Date.now()}={}){
 if(typeof journalPath!=='string'||typeof backupPath!=='string'||typeof privatePem!=='string'||typeof now!=='function')throw Error('invalid-backup-options');
 const src=safeFile(journalPath),dst=resolve(backupPath);
 if(src===dst||dst===src+'-wal'||dst===src+'-shm')throw Error('backup-overwrites-journal');
 if(existsSync(dst)||existsSync(dst+'.receipt.json'))throw Error('backup-already-exists');
 const createdAt=now();if(!Number.isSafeInteger(createdAt)||createdAt<0)throw Error('invalid-backup-time');
 mkdirSync(dirname(dst),{recursive:true,mode:0o700});
 const temp=mkdtempSync(join(dirname(dst),'.faraday-backup-tmp-'));let created=false;
 try{
  const snapshot=join(temp,'journal.sqlite'),db=new DatabaseSync(src,{readOnly:true});
  try{await backup(db,snapshot);}finally{db.close();}
  chmodSync(snapshot,0o600);
  const {operationCount}=inspect(snapshot),bytes=readFileSync(safeFile(snapshot));
  const manifest={format:'faraday-journal-backup',version:1,createdAt,operationCount,backupSha256:sha(bytes)};
  const signature=sign(null,Buffer.concat([PREFIX,encode(manifest)]),createPrivateKey(privatePem)).toString('base64url');
  copyFileSync(snapshot,dst,constants.COPYFILE_EXCL);created=true;chmodSync(dst,0o600);
  writeFileSync(dst+'.receipt.json',encode({manifest,signature}),{flag:'wx',mode:0o600});
  return {verified:true,operationCount,backupSha256:manifest.backupSha256,backupPath:dst,receiptPath:dst+'.receipt.json'};
 }catch(e){if(created){rmSync(dst,{force:true});rmSync(dst+'.receipt.json',{force:true});}throw e;}
 finally{rmSync(temp,{recursive:true,force:true});}
}
export function verifySignedJournalBackup({backupPath,receiptPath=backupPath+'.receipt.json',publicPem,expectedSha256,minCreatedAt}={}){
 if(typeof backupPath!=='string'||typeof receiptPath!=='string'||typeof publicPem!=='string')throw Error('invalid-backup-options');
 const b=safeFile(backupPath),r=safeFile(receiptPath,16384);
 let packet;try{packet=JSON.parse(readFileSync(r,'utf8'));}catch{throw Error('invalid-backup-manifest');}
 const manifest=checkSignature(packet,publicPem);
 if(expectedSha256!==undefined&&(!/^[a-f0-9]{64}$/.test(expectedSha256)||manifest.backupSha256!==expectedSha256))throw Error('backup-pin-mismatch');
 if(minCreatedAt!==undefined&&(!Number.isSafeInteger(minCreatedAt)||minCreatedAt<0||manifest.createdAt<minCreatedAt))throw Error('backup-rollback-detected');
 if(sha(readFileSync(b))!==manifest.backupSha256)throw Error('backup-hash-mismatch');
 const {operationCount}=inspect(b);
 if(operationCount!==manifest.operationCount)throw Error('backup-count-mismatch');
 return {verified:true,format:manifest.format,operationCount,backupSha256:manifest.backupSha256,executionRepeated:false};
}
export function restoreVerifiedJournalBackup({backupPath,receiptPath,restorePath,publicPem,expectedSha256,minCreatedAt}={}){
 if(typeof restorePath!=='string'||!restorePath||typeof backupPath!=='string')throw Error('invalid-restore-options');
 const src=resolve(backupPath),dst=resolve(restorePath);
 if(src===dst||existsSync(dst)||existsSync(dst+'-wal')||existsSync(dst+'-shm'))throw Error('restore-destination-exists');
 const evidence=verifySignedJournalBackup({backupPath,receiptPath:receiptPath||backupPath+'.receipt.json',publicPem,expectedSha256,minCreatedAt});
 mkdirSync(dirname(dst),{recursive:true,mode:0o700});
 copyFileSync(src,dst,constants.COPYFILE_EXCL);chmodSync(dst,0o600);
 try{if(sha(readFileSync(safeFile(dst)))!==evidence.backupSha256)throw Error('restore-hash-mismatch');if(inspect(dst).operationCount!==evidence.operationCount)throw Error('restore-validation-failed');}
 catch(e){rmSync(dst,{force:true});throw e;}
 return {...evidence,restorePath:dst,executionRepeated:false,requiresOperatorReview:true};
}
