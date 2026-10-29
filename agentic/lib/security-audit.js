/** Read-only local posture audit. Not an exploit scanner or production certification. */
import {lstatSync,readdirSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {discover} from './discover.js';
function state(path){
  let s;try{s=lstatSync(path);}catch(error){if(error.code==='ENOENT')return {exists:false};throw error;}
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
    add(name,!s.exists||s.secure===null?'review':s.secure===false?'fail':'pass',!s.exists?'Not created yet':s.secure===null?'Windows ACL not verified':'Permissions '+(s.mode??'unknown'));
  }
  const backups=join(dir,'targets');
  const s=state(backups);
  if(s.exists){
    add('config-backup-directory',s.secure===null?'review':s.secure===false?'fail':'pass',s.secure===null?'Windows ACL not verified':'Permissions '+(s.mode??'unknown'));
    if(s.secure!==false&&lstatSync(backups).isDirectory()){
      const entries=readdirSync(backups);
      if(entries.length>500)add('private-backup-file','review','More than 500 backups; remaining files not checked');
      for(const name of entries.slice(0,500)){
        if(state(join(backups,name)).secure===false)add('private-backup-file','fail','Insecure backup or symlink');
      }
    }
  }
  const failures=checks.filter(x=>x.status==='fail').length,reviews=checks.filter(x=>x.status==='review').length;
  return {name:'FARADAY local configuration audit',root:base,checks,failures,reviews,
    overall:failures?'needs-attention':reviews?'review-required':'no-local-issues-detected',
    limitations:'Does not verify workload identity, direct-API bypass, network isolation, TLS termination, hosts, or model supply chain.'};
}
