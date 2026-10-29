import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync,mkdtempSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
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