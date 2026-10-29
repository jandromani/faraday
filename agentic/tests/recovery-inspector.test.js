import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,symlinkSync,statSync} from 'node:fs';
import {tmpdir} from 'node:os';import {join} from 'node:path';
import {ExecutionJournal} from '../lib/pilot-receipts.js';
import {inspectRecovery} from '../lib/recovery-inspector.js';
function setup(t){const dir=mkdtempSync(join(tmpdir(),'faraday-recovery-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
  const path=join(dir,'journal.sqlite'),journal=new ExecutionJournal(path);return {path,journal,dir};}
test('E16 stale reserved operation flagged but never replayed or released',t=>{
  const x=setup(t);x.journal.reserve('test-stale','a'.repeat(64));
  const ts=x.journal.db.prepare('SELECT created_at FROM executions').get().created_at;
  const r=inspectRecovery({path:x.path,now:ts+70000,staleAfterMs:60000});
  assert.equal(r.summary.staleReserved,1);assert.equal(r.operations[0].operatorAction,'investigate-before-retrying');
  assert.throws(()=>x.journal.reserve('test-stale','a'.repeat(64)),/already-reserved/);
  assert.equal(x.journal.get('test-stale').state,'reserved');x.journal.close();
});
test('E16 read-only inspection survives journal close and process-like restart',t=>{
  const x=setup(t);x.journal.reserve('test-restart','b'.repeat(64));x.journal.finish('test-restart','upstream-uncertain',{claim:'synthetic'});x.journal.close();
  const size=statSync(x.path).size;
  const r=inspectRecovery({path:x.path,now:Date.now()+100000});
  assert.equal(r.summary.uncertain,1);assert.equal(r.operations[0].operatorAction,'read-only-reconciliation');
  assert.equal(statSync(x.path).size,size);
  const again=new ExecutionJournal(x.path);assert.equal(again.get('test-restart').state,'upstream-uncertain');again.close();
});
test('E16 completed operations are counted but not proposed for replay',t=>{
  const x=setup(t);x.journal.reserve('test-complete','c'.repeat(64));x.journal.finish('test-complete','simulated',{});
  assert.equal(inspectRecovery({path:x.path}).summary.completed,1);assert.equal(inspectRecovery({path:x.path}).operations.length,0);x.journal.close();
});
test('E16 future timestamps are flagged instead of treated as fresh reservations',t=>{
  const x=setup(t);
  try{
    x.journal.reserve('test-clock','c'.repeat(64));
    const ts=x.journal.db.prepare('SELECT created_at FROM executions').get().created_at;
    const report=inspectRecovery({path:x.path,now:ts-1});
    assert.equal(report.summary.clockAnomalies,1);assert.equal(report.summary.freshReserved,0);
    assert.equal(report.operations[0].ageMs,null);assert.equal(report.operations[0].operatorAction,'investigate-clock-before-retrying');
    assert.equal(x.journal.get('test-clock').state,'reserved');
  }finally{x.journal.close();}
});
test('E16 rejects invalid stale thresholds',t=>{
  const x=setup(t);try{assert.throws(()=>inspectRecovery({path:x.path,staleAfterMs:-1}),/Invalid recovery inspection/);}finally{x.journal.close();}
});
test('E16 prevents symlink journal',t=>{
  const x=setup(t),link=join(x.dir,'link.sqlite');
  try{
    try{symlinkSync(x.path,link);}catch(error){if(process.platform==='win32'&&error.code==='EPERM'){t.skip('Windows account cannot create symbolic links');return;}throw error;}
    assert.throws(()=>inspectRecovery({path:link}),/Unsafe recovery journal/);
  }finally{x.journal.close();}
});
