import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,writeFileSync,symlinkSync,rmSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {newIdentity} from '../lib/authority.js';
import {ExecutionJournal} from '../lib/pilot-receipts.js';
import {createSignedJournalBackup,verifySignedJournalBackup,restoreVerifiedJournalBackup} from '../lib/journal-backup.js';
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
 const link=join(dir,'link.sqlite');symlinkSync(journal,link);
 await assert.rejects(createSignedJournalBackup({journalPath:link,backupPath:join(dir,'bad.sqlite'),privatePem:key.privatePem}),/unsafe-backup-file/);
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
