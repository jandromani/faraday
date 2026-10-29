import test from 'node:test';
import assert from 'node:assert/strict';
import {newIdentity} from '../lib/authority.js';
import {signReleaseEvidence,verifyReleaseEvidence} from '../lib/release-evidence.js';
import {audit} from '../scripts/release-audit.mjs';
import {existsSync,mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {execFileSync} from 'node:child_process';

test('E28 offline signature binds package identity, artifact and inventory to a pinned key',()=>{
 const key=newIdentity(),artifact=Buffer.from('synthetic archive'),sbom=Buffer.from('{"files":[]}');
 const identity={packageName:'@faraday/agentic',packageVersion:'0.99.4'};
 const evidence=signReleaseEvidence({artifact,sbom,...identity,privatePem:key.privatePem});
 const options={artifact,sbom,evidence,publicPem:key.publicPem,expectedPackageName:identity.packageName,expectedPackageVersion:identity.packageVersion};
 assert.equal(verifyReleaseEvidence(options).verified,true);
 assert.throws(()=>verifyReleaseEvidence({...options,artifact:Buffer.from('altered')}),/release-hash-mismatch/);
 assert.throws(()=>verifyReleaseEvidence({...options,sbom:Buffer.from('{}')}),/release-hash-mismatch/);
 assert.throws(()=>verifyReleaseEvidence({...options,publicPem:newIdentity().publicPem}),/invalid-release-signature/);
 assert.throws(()=>verifyReleaseEvidence({...options,expectedPackageVersion:'0.99.5'}),/release-identity-mismatch/);
 assert.throws(()=>verifyReleaseEvidence({...options,evidence:{...evidence,claims:{...evidence.claims,packageVersion:'0.99.5'}},expectedPackageVersion:'0.99.5'}),/invalid-release-signature/);
 assert.throws(()=>verifyReleaseEvidence({...options,evidence:{...evidence,unexpected:true}}),/invalid-release-evidence/);
 assert.throws(()=>verifyReleaseEvidence({...options,expectedPackageName:undefined}),/release-identity-mismatch/);
});
test('E28 sign and verify the actual locally packed archive and inventory',t=>{
 const root=resolve(import.meta.dirname,'..'),temp=mkdtempSync(join(tmpdir(),'faraday-release-sign-'));
 t.after(()=>rmSync(temp,{recursive:true,force:true}));
 const options={cwd:root,encoding:'utf8'};
 const npmScript=join(dirname(process.execPath),'node_modules','npm','bin','npm-cli.js');
 const args=['pack','--json','--ignore-scripts','--pack-destination',temp];
 const packed=existsSync(npmScript)?execFileSync(process.execPath,[npmScript,...args],options):process.platform==='win32'?execFileSync('cmd.exe',['/d','/c','npm',...args],options):execFileSync('npm',args,options);
 const manifest=JSON.parse(packed)[0],artifact=readFileSync(join(temp,manifest.filename));
 const inventory=audit({project:root});assert.equal(inventory.ok,true);
 const sbom=Buffer.from(JSON.stringify(inventory.sbom)),key=newIdentity(),packageName=manifest.name,packageVersion=manifest.version;
 const evidence=signReleaseEvidence({artifact,sbom,packageName,packageVersion,privatePem:key.privatePem});
 const result=verifyReleaseEvidence({artifact,sbom,evidence,publicPem:key.publicPem,expectedPackageName:packageName,expectedPackageVersion:packageVersion});
 assert.equal(result.verified,true);assert.equal(result.artifactSha256.length,64);
});