#!/usr/bin/env node
/** Validates saved R2/R3 evidence references against actual bytes in a controlled workspace.
 * This does not certify the originating CI runner or external Vault/IdP.
 */
import {verifyEvidenceBundle} from '../lib/verified-evidence.js';
const [profile,manifestPath,pinnedCommit]=process.argv.slice(2);
const expectedCommit=process.env.GITHUB_SHA||pinnedCommit;
try{
 if(!expectedCommit)throw Error('GITHUB_SHA or explicit pinned commit is required');
 const result=verifyEvidenceBundle({root:process.cwd(),manifestPath,profile,expectedCommit});
 console.log(JSON.stringify(result,null,2));
 if(!result.manifestComplete)process.exitCode=2;
}catch(error){console.error('R2/R3 evidence verification failed: '+error.message);process.exitCode=2;}
