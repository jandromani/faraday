/** Read-only local posture audit. Not an exploit scanner or production certification. */
import {existsSync,lstatSync,readdirSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {discover} from './discover.js';
function state(path){
  if(!existsSync(path))return {exists:false};
  const s=lstatSync(path);
  if(s.isSymbolicLink()||!s.isFile()&&!s.isDirectory())return {exists:true,secure:false};
  const mode=s.mode&0o777;
  return {exists:true,secure:process.platform==='win32'?null:(mode&0o077)===0,mode:mode.toString(8).padStart(3,'0')};
}
export function auditWorkspace(root=process.cwd()){
  const base=resolve(root),dir=join(base,'.faraday'),db=join(dir,'graph.sqlite'),checks=[];
  const add=(name,status,detail)=>checks.push({name,status,detail});
  const report=discover({root:base});
  add('configuration-parse',report.warnings.length?'review':'pass',String(report.warnings.length)+' configuration warnings');
  for(const [name,path] of [['private-data-directory',dir],['graph-database',db]]){
    const s=state(path);
    add(name,!s.exists?'review':s.secure===false?'fail':'pass',s.exists?'Permissions '+(s.mode??'unknown'):'Not created yet');
  }
  const backups=join(dir,'targets');
  if(existsSync(backups)){
    const s=state(backups);
    add('config-backup-directory',s.secure===false?'fail':'pass','Permissions '+(s.mode??'unknown'));
    if(s.secure!==false&&lstatSync(backups).isDirectory()){
      for(const name of readdirSync(backups).slice(0,500)){
        if(state(join(backups,name)).secure===false)add('private-backup-file','fail','Insecure backup or symlink');
      }
    }
  }
  const failures=checks.filter(x=>x.status==='fail').length;
  return {name:'FARADAY local configuration audit',root:base,checks,failures,
    overall:failures?'needs-attention':'no-local-issues-detected',
    limitations:'Does not verify workload identity, direct-API bypass, network isolation, TLS termination, hosts, or model supply chain.'};
}
