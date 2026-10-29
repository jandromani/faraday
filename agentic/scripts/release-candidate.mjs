#!/usr/bin/env node
/** R1: Offline, fail-closed release-candidate packaging and archive/SBOM verification.
 * Integrity gate only; not independent provenance or a full dependency SBOM.
 */
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {existsSync,readFileSync,writeFileSync,mkdirSync,mkdtempSync,rmSync,lstatSync} from 'node:fs';
import {dirname,join,resolve,sep} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {audit} from './release-audit.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const assert=(cond,msg)=>{if(!cond)throw Error('release-candidate:'+msg);};
const safeRelative=x=>typeof x==='string'&&x.length>0&&x.length<512&&!x.includes('\\')&&!x.startsWith('/')&&x.split('/').every(p=>p&&p!=='.'&&p!=='..');
const shaFile=file=>digest(readFileSync(file));
const fileNameFor=version=>'faraday-agentic-'+version+'.tgz';
const manifestName='faraday-release-manifest.json',sbomName='faraday-source-inventory.spdx.json';
function runPack(out){
 const cmd=process.platform==='win32'?'cmd.exe':'npm';
 const args=process.platform==='win32'?['/d','/s','/c','npm','pack','--json','--ignore-scripts','--pack-destination',out]:['pack','--json','--ignore-scripts','--pack-destination',out];
 return JSON.parse(execFileSync(cmd,args,{cwd:root,encoding:'utf8',timeout:120000,maxBuffer:2e6}));
}
function checkInventory(archive,spdx){
 assert(spdx?.spdxVersion==='SPDX-2.3'&&Array.isArray(spdx.files),'invalid-spdx');
 const expected=new Map();
 for(const file of spdx.files){
  const name=file?.fileName?.replace(/^\.\//,'');
  assert(safeRelative(name)&&file.fileName==='./'+name&&!expected.has(name),'invalid-inventory-path');
  const hash=file?.checksums?.find(c=>c.algorithm==='SHA256')?.checksumValue;
  assert(typeof hash==='string'&&/^[a-f0-9]{64}$/.test(hash),'invalid-inventory-sha');
  expected.set(name,{hash,bytes:file.bytes});
 }
 const list=execFileSync('tar',['-tzf',archive],{encoding:'utf8',timeout:30000,maxBuffer:2e6}).split('\n').filter(Boolean);
 const names=new Set();
 for(const entry of list){
  assert(entry.startsWith('package/')&&safeRelative(entry),'unsafe-archive-path');
  const name=entry.slice('package/'.length);
  assert(expected.has(name)&&!names.has(name),'archive-inventory-mismatch');
  names.add(name);
 }
 assert(names.size===expected.size,'archive-file-count-mismatch');
 const temp=mkdtempSync(join(tmpdir(),'faraday-release-verify-'));
 try{
  execFileSync('tar',['-xzf',archive,'-C',temp,'--no-same-owner'],{timeout:30000,maxBuffer:2e6});
  for(const [name,entry] of expected){
   const file=resolve(temp,'package',name),prefix=resolve(temp,'package')+sep;
   assert(file.startsWith(prefix),'archive-path-escape');
   let st;try{st=lstatSync(file);}catch{throw Error('release-candidate:missing-in-archive');}
   assert(st.isFile()&&!st.isSymbolicLink()&&st.size===entry.bytes,'archive-entry-invalid');
   assert(shaFile(file)===entry.hash,'archive-file-hash-mismatch');
  }
 }finally{rmSync(temp,{recursive:true,force:true});}
 return expected.size;
}
export function createReleaseCandidate({out,commit}={}){
 assert(typeof out==='string'&&out.length>0,'missing-output-directory');
 assert(typeof commit==='string'&&/^[a-f0-9]{40}$/.test(commit),'invalid-commit');
 const abs=resolve(out),pkg=JSON.parse(readFileSync(join(root,'package.json'),'utf8'));
 assert(pkg.private===true,'preview-must-remain-private');
 assert(/^[0-9]+\.[0-9]+\.[0-9]+$/.test(pkg.version),'invalid-version');
 assert(!existsSync(join(abs,manifestName))&&!existsSync(join(abs,sbomName))&&!existsSync(join(abs,fileNameFor(pkg.version))),'output-already-exists');
 mkdirSync(abs,{recursive:true,mode:0o700});
 const inventory=audit({project:root});assert(inventory.ok&&inventory.count>0,'package-audit-failed');
 const packed=runPack(abs);assert(packed.length===1,'unexpected-pack-result');
 const m=packed[0],tgz=fileNameFor(pkg.version);
 assert(m.filename===tgz&&m.version===pkg.version&&m.name===pkg.name,'package-metadata-mismatch');
 const archive=join(abs,tgz);
 assert(existsSync(archive),'pack-missing');
 const n=checkInventory(archive,inventory.sbom);
 assert(n===m.files.length,'pack-inventory-different');
 const sbom=Buffer.from(JSON.stringify(inventory.sbom,null,2)+'\n');
 const manifest={format:'faraday-release-candidate/v1',packageName:pkg.name,version:pkg.version,
  commit,privatePreview:true,archive:tgz,archiveSha256:shaFile(archive),inventory:sbomName,
  inventorySha256:digest(sbom),filesVerified:n,
  securityAssurance:'Developer Preview; independently verified CI and provenance required before publishing'};
 writeFileSync(join(abs,sbomName),sbom,{flag:'wx',mode:0o600});
 writeFileSync(join(abs,manifestName),JSON.stringify(manifest,null,2)+'\n',{flag:'wx',mode:0o600});
 return manifest;
}
export function verifyReleaseCandidate({out,commit}={}){
 assert(typeof out==='string'&&out.length>0,'missing-output-directory');
 const abs=resolve(out),manifest=JSON.parse(readFileSync(join(abs,manifestName),'utf8'));
 assert(manifest.format==='faraday-release-candidate/v1'&&manifest.privatePreview===true,'invalid-manifest');
 assert(typeof manifest.commit==='string'&&/^[a-f0-9]{40}$/.test(manifest.commit),'invalid-commit');
 if(commit!==undefined)assert(manifest.commit===commit,'unexpected-commit');
 assert(typeof manifest.version==='string'&&/^[0-9]+\.[0-9]+\.[0-9]+$/.test(manifest.version),'invalid-version');
 assert(manifest.archive===fileNameFor(manifest.version)&&manifest.inventory===sbomName,'invalid-artifact-name');
 assert(/^[a-f0-9]{64}$/.test(manifest.archiveSha256)&&/^[a-f0-9]{64}$/.test(manifest.inventorySha256),'invalid-checksum');
 const archive=join(abs,manifest.archive),spdxPath=join(abs,manifest.inventory);
 assert(shaFile(archive)===manifest.archiveSha256&&shaFile(spdxPath)===manifest.inventorySha256,'artifact-sha-mismatch');
 const spdx=JSON.parse(readFileSync(spdxPath,'utf8'));
 assert(spdx.packages?.[0]?.name===manifest.packageName&&spdx.packages?.[0]?.versionInfo===manifest.version,'inventory-package-identity');
 const n=checkInventory(archive,spdx);assert(n===manifest.filesVerified,'archive-content-mismatch');
 return {verified:true,commit:manifest.commit,archive:manifest.archive,filesVerified:n};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const [mode,out,commit]=process.argv.slice(2);
  if(!['build','verify'].includes(mode))throw Error('usage: node scripts/release-candidate.mjs build|verify OUT [COMMIT]');
  const r=mode==='build'?createReleaseCandidate({out,commit}):verifyReleaseCandidate({out,commit});
  console.log(JSON.stringify(r));
 }catch(error){console.error(error.message);process.exitCode=2;}
}
