#!/usr/bin/env node
/** FARADAY package supply-chain inventory and offline secret safety gate.
 * Checks npm pack output, not unrelated repository files. Not an independent security audit.
 */
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFileSync,statSync,writeFileSync,lstatSync} from 'node:fs';
import {resolve,dirname,join,relative,isAbsolute,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const hash=x=>createHash('sha256').update(x).digest('hex');
const bannedName=/(^|\/)(\.env(?:\..+)?|\.npmrc|id_(?:rsa|ed25519)|.*\.(?:pem|key|p12|pfx|sqlite|db)|\.faraday)(\/|$)/i;
const suspicious=[/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, /\bsk-(?:proj-|or-v1-|live-)[A-Za-z0-9_-]{18,}/, /\bghp_[A-Za-z0-9]{30,}/];
export function audit({project=root,packFn}={}){
 const pkg=JSON.parse(readFileSync(join(project,'package.json'),'utf8'));
 const run=packFn??(()=>JSON.parse(process.platform==='win32'
   ?execFileSync('cmd.exe',['/d','/s','/c','npm pack --json --dry-run --ignore-scripts'],{cwd:project,encoding:'utf8'})
   :execFileSync('npm',['pack','--json','--dry-run','--ignore-scripts'],{cwd:project,encoding:'utf8'})));
 const result=run();if(!Array.isArray(result)||result.length!==1||!Array.isArray(result[0].files))throw Error('unrecognized-pack-manifest');
 const failures=[],files=[];
 for(const entry of result[0].files){
   const name=entry.path;
   if(typeof name!=='string'||name.startsWith('/')||name.includes('..')||name.includes('\\')||bannedName.test(name)){failures.push({path:String(name),reason:'unsafe-package-path'});continue;}
   const full=resolve(project,name);
   const relativeToProject=relative(resolve(project),full);
   if(!relativeToProject||relativeToProject==='..'||relativeToProject.startsWith('..'+sep)||isAbsolute(relativeToProject)){failures.push({path:name,reason:'path-escape'});continue;}
   const st=lstatSync(full);
   if(!st.isFile()||st.isSymbolicLink()){failures.push({path:name,reason:'nonregular-or-symlink'});continue;}
   const bytes=readFileSync(full),s=bytes.toString('utf8');
   if(suspicious.some(pattern=>pattern.test(s)))failures.push({path:name,reason:'secret-like-token'});
   files.push({fileName:'./'+name,bytes:st.size,checksums:[{algorithm:'SHA256',checksumValue:hash(bytes)}],SPDXID:'SPDXRef-File-'+files.length});
 }
 if(pkg.private!==true)failures.push({path:'package.json',reason:'private-preview-package-must-not-publish'});
 const digest=hash(JSON.stringify(files.map(f=>[f.fileName,f.checksums[0].checksumValue])));
 const sbom={spdxVersion:'SPDX-2.3',dataLicense:'CC0-1.0',SPDXID:'SPDXRef-DOCUMENT',name:pkg.name+'-'+pkg.version,
  documentNamespace:'https://faraday.example/sbom/'+digest,creationInfo:{creators:['Tool: FARADAY-release-audit/1'],created:new Date(Number(process.env.SOURCE_DATE_EPOCH??'0')*1000).toISOString()},
  packages:[{name:pkg.name,SPDXID:'SPDXRef-Package',versionInfo:pkg.version,downloadLocation:'NOASSERTION',filesAnalyzed:true,licenseDeclared:pkg.license||'NOASSERTION',copyrightText:'NOASSERTION'}],
  files,relationships:[{spdxElementId:'SPDXRef-DOCUMENT',relatedSpdxElement:'SPDXRef-Package',relationshipType:'DESCRIBES'},...files.map(f=>({spdxElementId:'SPDXRef-Package',relatedSpdxElement:f.SPDXID,relationshipType:'CONTAINS'}))]};
 return {ok:failures.length===0,failures,count:files.length,sha256:digest,sbom};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const report=audit();const out=process.argv[2];if(out)writeFileSync(resolve(out),JSON.stringify(report.sbom,null,2)+'\n',{flag:'wx',mode:0o600});
 console.log(JSON.stringify({ok:report.ok,files:report.count,manifestSha256:report.sha256,failures:report.failures,output:out||null}));if(!report.ok)process.exitCode=2;
 }catch(e){console.error('FARADAY release audit failed:',e.message);process.exitCode=2;}
}
