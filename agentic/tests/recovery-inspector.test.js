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
test('E16 prevents symlink journal and invalid stale thresholds',t=>{
  const x=setup(t),link=join(x.dir,'link.sqlite');symlinkSync(x.path,link);
  assert.throws(()=>inspectRecovery({path:link}),/Unsafe recovery journal/);
  assert.throws(()=>inspectRecovery({path:x.path,staleAfterMs:-1}),/Invalid recovery inspection/);x.journal.close();
});
