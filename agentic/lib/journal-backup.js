import {backup,DatabaseSync} from 'node:sqlite';
import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {chmodSync,lstatSync,mkdtempSync,mkdirSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {dirname,join,resolve} from 'node:path';
import {tmpdir} from 'node:os';

const PREFIX=Buffer.from('FARADAY-JOURNAL-BACKUP-V1\0');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const encode=value=>Buffer.from(JSON.stringify(value));
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const pathExists=path=>{try{lstatSync(path);return true;}catch(error){if(error.code==='ENOENT')return false;throw error;}};
function safeFile(file,max=100*1024*1024){
  if(typeof file!=='string'||!file)throw Error('invalid-backup-options');
  const path=resolve(file),stat=lstatSync(path);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.size<100||stat.size>max)throw Error('unsafe-backup-file');
  return path;
}
function inspect(file){
  const db=new DatabaseSync(file,{readOnly:true});
  try{
    const integrity=db.prepare('PRAGMA integrity_check').get();
    if(!integrity||Object.values(integrity)[0]!=='ok')throw Error('sqlite-integrity-failed');
    const tables=db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('executions','reconciliation_history')").all().map(row=>row.name);
    if(!tables.includes('executions')||!tables.includes('reconciliation_history'))throw Error('unexpected-journal-schema');
    const operationCount=db.prepare('SELECT COUNT(*) AS n FROM executions').get().n;
    if(!Number.isSafeInteger(operationCount)||operationCount<0||operationCount>10000000)throw Error('invalid-journal-count');
    return operationCount;
  }finally{db.close();}
}
function checkSignature(packet,publicPem){
  if(!exact(packet,['manifest','signature'])||!exact(packet.manifest,['format','version','createdAt','operationCount','backupSha256']))throw Error('invalid-backup-manifest');
  const {manifest,signature}=packet;
  if(manifest.format!=='faraday-journal-backup'||manifest.version!==1||typeof manifest.backupSha256!=='string'||!/^[a-f0-9]{64}$/.test(manifest.backupSha256)||!Number.isSafeInteger(manifest.createdAt)||manifest.createdAt<0||!Number.isSafeInteger(manifest.operationCount)||manifest.operationCount<0||typeof signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signature)||Buffer.from(signature,'base64url').toString('base64url')!==signature)throw Error('invalid-backup-manifest');
  let valid=false;try{const key=createPublicKey(publicPem);valid=key.asymmetricKeyType==='ed25519'&&verify(null,Buffer.concat([PREFIX,encode(manifest)]),key,Buffer.from(signature,'base64url'));}catch{}
  if(!valid)throw Error('invalid-backup-signature');
  return manifest;
}
export async function createSignedJournalBackup({journalPath,backupPath,privatePem,now=()=>Date.now()}={}){
  if(typeof backupPath!=='string'||!backupPath||typeof privatePem!=='string'||typeof now!=='function')throw Error('invalid-backup-options');
  const source=safeFile(journalPath),destination=resolve(backupPath);
  if(source===destination||destination===source+'-wal'||destination===source+'-shm')throw Error('backup-overwrites-journal');
  if(pathExists(destination)||pathExists(destination+'.receipt.json'))throw Error('backup-already-exists');
  const createdAt=now();if(!Number.isSafeInteger(createdAt)||createdAt<0)throw Error('invalid-backup-time');
  const key=createPrivateKey(privatePem);if(key.asymmetricKeyType!=='ed25519')throw Error('invalid-backup-key');
  mkdirSync(dirname(destination),{recursive:true,mode:0o700});
  const temp=mkdtempSync(join(dirname(destination),'.faraday-backup-'));let created=false;
  try{
    const snapshot=join(temp,'journal.sqlite'),db=new DatabaseSync(source,{readOnly:true});
    try{await backup(db,snapshot);}finally{db.close();}
    const operationCount=inspect(snapshot),bytes=readFileSync(safeFile(snapshot));
    const manifest={format:'faraday-journal-backup',version:1,createdAt,operationCount,backupSha256:sha(bytes)};
    const signature=sign(null,Buffer.concat([PREFIX,encode(manifest)]),key).toString('base64url');
    writeFileSync(destination,bytes,{flag:'wx',mode:0o600});created=true;
    writeFileSync(destination+'.receipt.json',encode({manifest,signature}),{flag:'wx',mode:0o600});
    return {created:true,createdAt,operationCount,backupSha256:manifest.backupSha256,backupPath:destination,receiptPath:destination+'.receipt.json'};
  }catch(error){if(created)rmSync(destination,{force:true});throw error;}
  finally{rmSync(temp,{recursive:true,force:true});}
}
function verifiedBytes({backupPath,receiptPath=backupPath+'.receipt.json',publicPem,expectedSha256,minCreatedAt}={}){
  if(typeof publicPem!=='string')throw Error('invalid-backup-options');
  let packet;try{packet=JSON.parse(readFileSync(safeFile(receiptPath,16384),'utf8'));}catch{throw Error('invalid-backup-manifest');}
  const manifest=checkSignature(packet,publicPem);
  if(expectedSha256!==undefined&&(typeof expectedSha256!=='string'||!/^[a-f0-9]{64}$/.test(expectedSha256)||manifest.backupSha256!==expectedSha256))throw Error('backup-pin-mismatch');
  if(minCreatedAt!==undefined&&(!Number.isSafeInteger(minCreatedAt)||minCreatedAt<0||manifest.createdAt<minCreatedAt))throw Error('backup-rollback-detected');
  const bytes=readFileSync(safeFile(backupPath));
  if(bytes.length>100*1024*1024||sha(bytes)!==manifest.backupSha256)throw Error('backup-hash-mismatch');
  const temp=mkdtempSync(join(tmpdir(),'faraday-verify-'));
  try{
    const snapshot=join(temp,'journal.sqlite');writeFileSync(snapshot,bytes,{flag:'wx',mode:0o600});
    if(inspect(snapshot)!==manifest.operationCount)throw Error('backup-count-mismatch');
  }finally{rmSync(temp,{recursive:true,force:true});}
  return {bytes,manifest};
}
export function verifySignedJournalBackup(options={}){
  const {manifest}=verifiedBytes(options);
  return {verified:true,format:manifest.format,createdAt:manifest.createdAt,operationCount:manifest.operationCount,backupSha256:manifest.backupSha256,executionRepeated:false};
}
export function restoreVerifiedJournalBackup({backupPath,receiptPath,restorePath,publicPem,expectedSha256,minCreatedAt}={}){
  if(typeof restorePath!=='string'||!restorePath||typeof backupPath!=='string')throw Error('invalid-restore-options');
  const destination=resolve(restorePath);
  if(destination===resolve(backupPath)||pathExists(destination)||pathExists(destination+'-wal')||pathExists(destination+'-shm'))throw Error('restore-destination-exists');
  const {bytes,manifest}=verifiedBytes({backupPath,receiptPath:receiptPath??backupPath+'.receipt.json',publicPem,expectedSha256,minCreatedAt});
  mkdirSync(dirname(destination),{recursive:true,mode:0o700});
  writeFileSync(destination,bytes,{flag:'wx',mode:0o600});
  try{if(sha(readFileSync(destination))!==manifest.backupSha256)throw Error('restore-hash-mismatch');if(process.platform!=='win32')chmodSync(destination,0o600);}
  catch(error){rmSync(destination,{force:true});throw error;}
  return {verified:true,format:manifest.format,createdAt:manifest.createdAt,operationCount:manifest.operationCount,backupSha256:manifest.backupSha256,restorePath:destination,executionRepeated:false,requiresOperatorReview:true};
}