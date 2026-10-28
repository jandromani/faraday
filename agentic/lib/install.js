import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, unlinkSync, chmodSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { configServers } from './discover.js';

const object = x => x && typeof x === 'object' && !Array.isArray(x);
const safeFile = (path,data,mode=0o600) => {
  const temp=path+'.tmp-'+process.pid;
  try {
    writeFileSync(temp,data,{encoding:'utf8',flag:'wx',mode});
    chmodSync(temp,mode);
    renameSync(temp,path);
  } catch(e) {try{unlinkSync(temp);}catch{}throw e;}
};
function locate(config,server){
  const matches=[];
  for(const key of ['mcpServers','servers']) {
    if(object(config[key])&&Object.hasOwn(config[key],server))matches.push(key);
  }
  if(matches.length!==1)throw Error('Server missing or ambiguous');
  return matches[0];
}
function targetFile(configFile,server){
  const p=resolve(configFile);
  const id=createHash('sha256').update(p+'\0'+server).digest('hex').slice(0,24);
  const dir=join(dirname(p),'.faraday','targets');
  return {dir,file:join(dir,id+'.json')};
}
export function installProxy({configFile,server,db,binPath,nodePath}) {
  if(!server||!configFile)throw Error('install requires --config and --server');
  const path=resolve(configFile);
  const text=readFileSync(path,'utf8');
  // Rewriting JSONC would destroy user comments. Refuse rather than silently do so.
  let json;
  try {json=JSON.parse(text);} catch {throw Error('Auto-install requires strict JSON; use hook for commented JSONC files');}
  const key=locate(json,server);
  const original=json[key][server];
  if(!object(original)||configServers({[key]:{[server]:original}})[0]?.transport!=='stdio')
    throw Error('Auto-install supports only valid stdio MCP server entries');
  if(typeof original.command!=='string'||!original.command)throw Error('Missing server command');
  const {dir,file}=targetFile(path,server);
  if(existsSync(file))throw Error('Already installed; use uninstall before reinstall');
  mkdirSync(dir,{recursive:true,mode:0o700});
  chmodSync(dir,0o700);
  const source={ [key]:{[server]:original} };
  // Backup contains original launch command, arguments and possibly credentials.
  // It is never committed or printed; owners should protect their local files.
  writeFileSync(file,JSON.stringify(source,null,2)+'\n',{encoding:'utf8',flag:'wx',mode:0o600});
  chmodSync(file,0o600);
  const proxy={command:nodePath,args:[binPath,'proxy','--config',file,'--server',server,'--db',resolve(db)]};
  try {
    json[key][server]=proxy;
    const mode=statSync(path).mode & 0o777;
    safeFile(path,JSON.stringify(json,null,2)+'\n',mode);
  } catch(e) { try {unlinkSync(file);}catch{} throw e; }
  return {server,config:path,backup:file,db:resolve(db)};
}
export function uninstallProxy({configFile,server}) {
  if(!server||!configFile)throw Error('uninstall requires --config and --server');
  const path=resolve(configFile);
  const {file}=targetFile(path,server);
  if(!existsSync(file))throw Error('FARADAY backup not found');
  const current=JSON.parse(readFileSync(path,'utf8'));
  const previous=JSON.parse(readFileSync(file,'utf8'));
  const key=locate(previous,server);
  const activeKey=locate(current,server);
  if(key!==activeKey||!Array.isArray(current[key][server]?.args)
      ||current[key][server].args[1]!=='proxy'
      ||current[key][server].args[3]!==file) {
    throw Error('Config changed: refusing to overwrite; restore manually from private backup');
  }
  current[key][server]=previous[key][server];
  const mode=statSync(path).mode & 0o777;
  safeFile(path,JSON.stringify(current,null,2)+'\n',mode);
  unlinkSync(file);
  return {server,config:path};
}
