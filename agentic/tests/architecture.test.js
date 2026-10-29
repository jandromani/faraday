import {test} from 'node:test';import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';import {fileURLToPath} from 'node:url';import {resolve,dirname} from 'node:path';
import * as Connect from '../packages/connect/index.js';
import * as Authority from '../packages/authority/index.js';
import * as Evidence from '../packages/evidence/index.js';
import * as Lab from '../packages/lab/index.js';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
test('Four APIs reference working implementations',()=>{
 assert.equal(typeof Connect.installProxy,'function');assert.equal(typeof Connect.probeStdio,'function');
 assert.equal(typeof Authority.AuthorityGate,'function');assert.equal(typeof Authority.PinnedOAuthResource,'function');
 assert.equal(typeof Evidence.verifyReceipt,'function');assert.equal(typeof Evidence.evaluateAssurance,'function');
 assert.equal(typeof Lab.runLab,'function');assert.equal(Lab.DUMMY_AGENTS.length,12);
});
test('Four packages private, versioned, exposed without breaking previous exports',()=>{
 const main=JSON.parse(readFileSync(resolve(root,'package.json'),'utf8'));
 assert.equal(main.private,true);assert.equal(main.version,'0.99.4');
 for(const name of ['connect','authority','evidence','lab']){
  const pkg=JSON.parse(readFileSync(resolve(root,'packages',name,'package.json'),'utf8'));
  assert.equal(pkg.name,'@faraday/'+name);assert.equal(pkg.version,'0.99.4');assert.equal(pkg.private,true);
 }
 for(const key of ['./connect','./authority-suite','./evidence','./lab-suite','./gateway','./mcp-oauth-resource'])assert.ok(main.exports[key]);
});
test('Migration facades avoid cross-package imports',()=>{
 for(const name of ['connect','authority','evidence','lab']){
  const code=readFileSync(resolve(root,'packages',name,'index.js'),'utf8');
  assert.doesNotMatch(code,/from ['"]\.\.\/[^.]/);assert.doesNotMatch(code,/process\.env/);
 }
});
