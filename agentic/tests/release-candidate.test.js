import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createReleaseCandidate,verifyReleaseCandidate} from '../scripts/release-candidate.mjs';

const COMMIT='a'.repeat(40);
test('R1 preview archive exactly matches SPDX file hashes and source commit', {skip:process.platform!=='linux'}, t=>{
 const root=mkdtempSync(join(tmpdir(),'faraday-release-accept-'));t.after(()=>rmSync(root,{recursive:true,force:true}));
 const result=createReleaseCandidate({out:root,commit:COMMIT});
 assert.equal(result.privatePreview,true);assert.ok(result.filesVerified>10);
 assert.equal(verifyReleaseCandidate({out:root,commit:COMMIT}).verified,true);
 assert.throws(()=>verifyReleaseCandidate({out:root,commit:'b'.repeat(40)}),/unexpected-commit/);
 const inventory=join(root,result.inventory),content=readFileSync(inventory,'utf8');
 writeFileSync(inventory,content+'\n');
 assert.throws(()=>verifyReleaseCandidate({out:root,commit:COMMIT}),/artifact-sha-mismatch/);
 writeFileSync(inventory,content);
 const archive=join(root,result.archive),original=readFileSync(archive),tampered=Buffer.from(original);
 tampered[Math.floor(tampered.length/2)]^=1;writeFileSync(archive,tampered);
 assert.throws(()=>verifyReleaseCandidate({out:root,commit:COMMIT}),/artifact-sha-mismatch/);
 writeFileSync(archive,original);
 assert.equal(verifyReleaseCandidate({out:root,commit:COMMIT}).verified,true);
 assert.throws(()=>createReleaseCandidate({out:root,commit:COMMIT}),/output-already-exists/);
});
