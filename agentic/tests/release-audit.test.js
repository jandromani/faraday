import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {audit} from '../scripts/release-audit.mjs';
function setup(t){const d=mkdtempSync(join(tmpdir(),'faraday-release-audit-'));t.after(()=>rmSync(d,{recursive:true,force:true}));writeFileSync(join(d,'package.json'),JSON.stringify({name:'@faraday/agentic',version:'0.97.0',private:true,license:'Apache-2.0'}));writeFileSync(join(d,'index.js'),'export const ok=true;');const entries=['package.json','index.js'];return {d,entries,run:()=>audit({project:d,packFn:()=>[{files:entries.map(path=>({path}))}]})};}
test('E28 SPDX inventory covers all packed files and their SHA256',t=>{const x=setup(t);const a=x.run(),b=x.run();assert.equal(a.ok,true);assert.equal(a.count,2);assert.equal(a.sha256,b.sha256);assert.equal(a.sbom.spdxVersion,'SPDX-2.3');assert.ok(a.sbom.files.every(f=>f.checksums[0].algorithm==='SHA256'));});
test('E28 reject private key file paths',t=>{const x=setup(t);x.entries.push('secret.pem');writeFileSync(join(x.d,'secret.pem'),'PRIVATE KEY');assert.equal(x.run().ok,false);assert.equal(x.run().failures[0].reason,'unsafe-package-path');});
test('E28 reject inline private keys in permitted files',t=>{const x=setup(t);writeFileSync(join(x.d,'index.js'),'-----BEGIN PRIVATE KEY-----\nprivate\n');assert.equal(x.run().ok,false);});
test('E28 package cannot silently turn npm-public',t=>{const x=setup(t);writeFileSync(join(x.d,'package.json'),JSON.stringify({name:'@faraday/agentic',version:'0.97.0',private:false,license:'Apache-2.0'}));assert.equal(x.run().ok,false);});