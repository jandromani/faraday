import {test} from 'node:test';import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {resolve,dirname} from 'node:path';
import * as Connect from '../packages/connect/index.js';
import * as Authority from '../packages/authority/index.js';
import * as Evidence from '../packages/evidence/index.js';
import * as Lab from '../packages/lab/index.js';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
test('Four migration API surfaces bind to real existing implementations',()=>{
  assert.equal(typeof Connect.installProxy,'function');assert.equal(typeof Connect.probeStdio,'function');
  assert.equal(typeof Authority.AuthorityGate,'function');assert.equal(typeof Authority.PinnedOAuthResource,'function');assert.equal(typeof Authority.LocalOAuthRevocations,'function');assert.equal(typeof Authority.createStrictSecretFileProvider,'function');
  assert.equal(typeof Evidence.verifyReceipt,'function');assert.equal(typeof Evidence.evaluateAssurance,'function');assert.equal(typeof Evidence.verifyWitnessedEvidence,'function');
  assert.equal(typeof Lab.runLab,'function');assert.equal(Lab.DUMMY_AGENTS.length,12);
});
test('All packages are private, individually versioned, and exposed without breaking historical exports',()=>{
  const main=JSON.parse(readFileSync(resolve(root,'package.json'),'utf8'));
  assert.equal(main.private,true);assert.equal(main.version,'0.99.5');
  for(const name of ['connect','authority','evidence','lab']){
    const pkg=JSON.parse(readFileSync(resolve(root,'packages',name,'package.json'),'utf8'));
    assert.equal(pkg.name,'@faraday/'+name);assert.equal(pkg.version,'0.99.5');assert.equal(pkg.private,true);
  }
  for(const key of ['./connect','./authority-suite','./evidence','./lab-suite','./gateway','./mcp-oauth-resource'])assert.ok(main.exports[key]);
});
test('Architecture migration facades have no cross-package imports',()=>{
  for(const name of ['connect','authority','evidence','lab']){
    const s=readFileSync(resolve(root,'packages',name,'index.js'),'utf8');
    assert.doesNotMatch(s,/from ['"]\.\.\/[^.]/);assert.doesNotMatch(s,/process\.env/);
  }
});
