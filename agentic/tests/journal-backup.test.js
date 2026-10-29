import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync,mkdtempSync,readFileSync,writeFileSync,symlinkSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {newIdentity} from '../lib/authority.js';
import {ExecutionJournal} from '../lib/pilot-receipts.js';
import {createSignedJournalBackup,verifySignedJournalBackup,restoreVerifiedJournalBackup} from '../lib/journal-backup.js';

test('signed online backup restores a snapshot to a new journal without replay',async t=>{
  const dir=mkdtempSync(join(tmpdir(),'faraday-backup-')),path=join(dir,'journal.sqlite'),backupPath=join(dir,'backup.sqlite'),restorePath=join(dir,'restored.sqlite');
  const journal=new ExecutionJournal(path),key=newIdentity();
  t.after(()=>{journal.close();rmSync(dir,{recursive:true,force:true});});
  journal.reserve('synthetic-operation-1','hash-1');journal.finish('synthetic-operation-1','upstream-uncertain',{claim:'synthetic'});
  const approvalEvidence={approvalDigest:'synthetic-digest',bundle:[{claims:{approver:'synthetic'},signature:'synthetic'}]};
  journal.reserve('synthetic-operation-2','hash-2',{approvalEvidence});
  const result=await createSignedJournalBackup({journalPath:path,backupPath,privatePem:key.privatePem,now:()=>10000});
  assert.equal(result.created,true);assert.equal(result.verified,undefined);assert.equal(result.createdAt,10000);
  journal.reserve('synthetic-operation-3','hash-3');
  assert.equal(verifySignedJournalBackup({backupPath,publicPem:key.publicPem,expectedSha256:result.backupSha256,minCreatedAt:10000}).operationCount,2);
  assert.equal(restoreVerifiedJournalBackup({backupPath,restorePath,publicPem:key.publicPem,expectedSha256:result.backupSha256}).executionRepeated,false);
  const restored=new ExecutionJournal(restorePath);
  try{assert.equal(restored.get('synthetic-operation-1').state,'upstream-uncertain');assert.equal(restored.get('synthetic-operation-2').state,'reserved');assert.deepEqual(restored.getApprovalEvidence('synthetic-operation-2'),approvalEvidence);assert.equal(restored.get('synthetic-operation-3'),null);assert.throws(()=>restored.reserve('synthetic-operation-2','hash-2'),/already-reserved/);}finally{restored.close();}
  assert.throws(()=>restoreVerifiedJournalBackup({backupPath,restorePath,publicPem:key.publicPem}),/destination-exists/);
  const occupied=join(dir,'occupied.sqlite');writeFileSync(occupied+'-wal','synthetic');
  assert.throws(()=>restoreVerifiedJournalBackup({backupPath,restorePath:occupied,publicPem:key.publicPem}),/destination-exists/);
  assert.throws(()=>verifySignedJournalBackup({backupPath,publicPem:key.publicPem,minCreatedAt:10001}),/rollback-detected/);
  assert.throws(()=>verifySignedJournalBackup({backupPath,publicPem:key.publicPem,expectedSha256:'0'.repeat(64)}),/pin-mismatch/);
});
test('signed backup rejects wrong keys and tampering',async t=>{
  const dir=mkdtempSync(join(tmpdir(),'faraday-backup-')),path=join(dir,'journal.sqlite'),backupPath=join(dir,'backup.sqlite');
  const journal=new ExecutionJournal(path),key=newIdentity();t.after(()=>{journal.close();rmSync(dir,{recursive:true,force:true});});
  journal.reserve('synthetic-operation-1','hash-1');await createSignedJournalBackup({journalPath:path,backupPath,privatePem:key.privatePem});
  assert.throws(()=>verifySignedJournalBackup({backupPath,publicPem:newIdentity().publicPem}),/invalid-backup-signature/);
  const receiptPath=backupPath+'.receipt.json',receipt=readFileSync(receiptPath),packet=JSON.parse(receipt);packet.manifest.operationCount=999;
  writeFileSync(receiptPath,JSON.stringify(packet));assert.throws(()=>verifySignedJournalBackup({backupPath,publicPem:key.publicPem}),/invalid-backup-signature/);
  writeFileSync(receiptPath,receipt);const bytes=readFileSync(backupPath);bytes[bytes.length-5]^=1;writeFileSync(backupPath,bytes);
  assert.throws(()=>verifySignedJournalBackup({backupPath,publicPem:key.publicPem}),/backup-hash-mismatch/);
});
test('recovery CLI backs up, verifies and restores a new journal',async t=>{
  const dir=mkdtempSync(join(tmpdir(),'faraday-backup-cli-')),path=join(dir,'journal.sqlite'),backupPath=join(dir,'backup.sqlite'),restorePath=join(dir,'restored.sqlite');
  const journal=new ExecutionJournal(path),key=newIdentity(),privatePath=join(dir,'key.pem'),publicPath=join(dir,'public.pem');
  t.after(()=>{journal.close();rmSync(dir,{recursive:true,force:true});});
  writeFileSync(privatePath,key.privatePem,{mode:0o600});writeFileSync(publicPath,key.publicPem,{mode:0o600});journal.reserve('synthetic-operation','hash');
  const command=args=>{const result=spawnSync(process.execPath,['bin/faraday.js','recovery',...args],{encoding:'utf8',timeout:15000});assert.equal(result.status,0,result.stderr);return JSON.parse(result.stdout);};
  const snapshot=command(['backup','--db',path,'--out',backupPath,'--private-key',privatePath]);
  assert.equal(command(['verify','--backup-file',backupPath,'--public-key',publicPath,'--expected-sha256',snapshot.backupSha256]).verified,true);
  const restored=command(['restore','--backup-file',backupPath,'--out',restorePath,'--public-key',publicPath,'--expected-sha256',snapshot.backupSha256]);
  assert.equal(restored.executionRepeated,false);assert.equal(restored.requiresOperatorReview,true);
  assert.equal(command(['inspect','--db',restorePath]).summary.total,1);
});
test('online backup includes committed rows still in SQLite WAL',async t=>{
  const dir=mkdtempSync(join(tmpdir(),'faraday-backup-wal-')),path=join(dir,'journal.sqlite'),backupPath=join(dir,'backup.sqlite'),restorePath=join(dir,'restored.sqlite');
  const journal=new ExecutionJournal(path),key=newIdentity();t.after(()=>{journal.close();rmSync(dir,{recursive:true,force:true});});
  journal.db.exec('PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0');journal.reserve('synthetic-wal-operation','hash');
  assert.equal(existsSync(path+'-wal'),true);
  await createSignedJournalBackup({journalPath:path,backupPath,privatePem:key.privatePem});
  restoreVerifiedJournalBackup({backupPath,restorePath,publicPem:key.publicPem});
  const restored=new ExecutionJournal(restorePath);try{assert.equal(restored.get('synthetic-wal-operation').state,'reserved');}finally{restored.close();}
});
const withTmp=async fn=>{const dir=mkdtempSync(join(tmpdir(),'faraday-backup-'));try{await fn(dir);}finally{rmSync(dir,{recursive:true,force:true});}};
function fixture(dir){const journal=join(dir,'operations.sqlite');const j=new ExecutionJournal(journal);j.reserve('synthetic-001','hash-001');j.reserve('synthetic-002','hash-002');return {journal,j};}
test('online backup signs snapshot and restores without replaying effects',async()=>withTmp(async dir=>{
 const {journal,j}=fixture(dir),key=newIdentity(),backupPath=join(dir,'private','snapshot.sqlite');
 const result=await createSignedJournalBackup({journalPath:journal,backupPath,privatePem:key.privatePem,now:()=>123456789});
 assert.equal(result.operationCount,2);j.reserve('synthetic-003','hash-003');
 assert.equal(verifySignedJournalBackup({backupPath,publicPem:key.publicPem}).operationCount,2);
 const restored=restoreVerifiedJournalBackup({backupPath,restorePath:join(dir,'restored.sqlite'),publicPem:key.publicPem});
 assert.equal(restored.requiresOperatorReview,true);assert.equal(restored.executionRepeated,false);
 assert.equal(restored.operationCount,2);assert.equal(j.get('synthetic-003').state,'reserved');j.close();
}));
test('reject existing destination, journal overwrite and symlink source',async()=>withTmp(async dir=>{
 const {journal,j}=fixture(dir),key=newIdentity(),bak=join(dir,'snapshot.sqlite');
 await assert.rejects(createSignedJournalBackup({journalPath:journal,backupPath:journal,privatePem:key.privatePem}),/backup-overwrites-journal/);
 await createSignedJournalBackup({journalPath:journal,backupPath:bak,privatePem:key.privatePem});
 await assert.rejects(createSignedJournalBackup({journalPath:journal,backupPath:bak,privatePem:key.privatePem}),/backup-already-exists/);
 if(process.platform!=='win32'){
  const link=join(dir,'link.sqlite');symlinkSync(journal,link);
  await assert.rejects(createSignedJournalBackup({journalPath:link,backupPath:join(dir,'bad.sqlite'),privatePem:key.privatePem}),/unsafe-backup-file/);
 }
 assert.throws(()=>restoreVerifiedJournalBackup({backupPath:bak,restorePath:journal,publicPem:key.publicPem}),/restore-destination-exists/);j.close();
}));
test('tampering with signed manifest or database is rejected offline',async()=>withTmp(async dir=>{
 const {journal,j}=fixture(dir),key=newIdentity(),bak=join(dir,'snapshot.sqlite');
 await createSignedJournalBackup({journalPath:journal,backupPath:bak,privatePem:key.privatePem});
 assert.throws(()=>verifySignedJournalBackup({backupPath:bak,publicPem:newIdentity().publicPem}),/invalid-backup-signature/);
 const receipt=bak+'.receipt.json',original=readFileSync(receipt),payload=JSON.parse(original);
 payload.manifest.operationCount=999;writeFileSync(receipt,JSON.stringify(payload));
 assert.throws(()=>verifySignedJournalBackup({backupPath:bak,publicPem:key.publicPem}),/invalid-backup-signature/);
 writeFileSync(receipt,original);const bytes=readFileSync(bak);bytes[bytes.length-5]^=1;writeFileSync(bak,bytes);
 assert.throws(()=>verifySignedJournalBackup({backupPath:bak,publicPem:key.publicPem}),/backup-hash-mismatch/);j.close();
}));
test('CLI backup verify restore cycle without modifying original journal',async()=>withTmp(async dir=>{
 const {journal,j}=fixture(dir),key=newIdentity(),priv=join(dir,'priv.pem'),pub=join(dir,'pub.pem'),bak=join(dir,'backup.sqlite'),dst=join(dir,'restored.sqlite');
 writeFileSync(priv,key.privatePem,{mode:0o600});writeFileSync(pub,key.publicPem,{mode:0o600});
 const command=parts=>{const r=spawnSync(process.execPath,['bin/faraday.js','recovery',...parts],
  {cwd:new URL('../',import.meta.url),encoding:'utf8',timeout:12000});assert.equal(r.status,0,r.stderr);return JSON.parse(r.stdout);};
 assert.equal(command(['backup','--db',journal,'--out',bak,'--private-key',priv]).operationCount,2);
 assert.equal(command(['verify','--backup-file',bak,'--public-key',pub]).verified,true);
 const done=command(['restore','--backup-file',bak,'--out',dst,'--public-key',pub]);
 assert.equal(done.executionRepeated,false);assert.equal(done.requiresOperatorReview,true);
 j.reserve('synthetic-003','hash-003');assert.equal(j.get('synthetic-003').state,'reserved');j.close();
}));

test('independently pinned digest and minimum time reject an older valid signed backup',async()=>withTmp(async dir=>{
 const {journal,j}=fixture(dir),key=newIdentity(),backupPath=join(dir,'snapshot.sqlite');
 const signed=await createSignedJournalBackup({journalPath:journal,backupPath,privatePem:key.privatePem,now:()=>10000});
 assert.equal(verifySignedJournalBackup({backupPath,publicPem:key.publicPem,expectedSha256:signed.backupSha256,minCreatedAt:10000}).verified,true);
 assert.throws(()=>verifySignedJournalBackup({backupPath,publicPem:key.publicPem,expectedSha256:'0'.repeat(64)}),/backup-pin-mismatch/);
 assert.throws(()=>verifySignedJournalBackup({backupPath,publicPem:key.publicPem,minCreatedAt:10001}),/backup-rollback-detected/);
 assert.throws(()=>restoreVerifiedJournalBackup({backupPath,restorePath:join(dir,'restore.sqlite'),publicPem:key.publicPem,minCreatedAt:10001}),/backup-rollback-detected/);
 j.close();
}));
