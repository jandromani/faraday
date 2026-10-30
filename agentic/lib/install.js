import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, unlinkSync, chmodSync, statSync, lstatSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { configServers } from './discover.js';
import { configuredHttpServer } from './http-bridge.js';
import {protectWindowsAcl,verifyWindowsAcl} from './windows-backup-acl.js';
import {loadToolPolicy} from './security-policy.js';

const object = x => x && typeof x === 'object' && !Array.isArray(x);
const safeFile = (path,data,mode=0o600) => {
  const temp=path+'.tmp-'+process.pid;
  try {
    writeFileSync(temp,data,{encoding:'utf8',flag:'wx',mode});
    if(process.platform==='win32')protectWindowsAcl(temp);
    else chmodSync(temp,mode);
    renameSync(temp,path);
    if(process.platform==='win32')verifyWindowsAcl(path);
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
export function installProxy({configFile,server,db,binPath,nodePath,dryRun=false,policyFile}) {
  if(!server||!configFile)throw Error('install requires --config and --server');
  const path=resolve(configFile);
  if(lstatSync(path).isSymbolicLink()) throw Error('Refusing symlinked MCP configuration');
  const text=readFileSync(path,'utf8');
  // Rewriting JSONC would destroy user comments. Refuse rather than silently do so.
  let json;
  try {json=JSON.parse(text);} catch {throw Error('Auto-install requires strict JSON; use hook for commented JSONC files');}
  const key=locate(json,server);
  const original=json[key][server];
  if(!object(original)) throw Error('Invalid MCP server entry');
  const transport=configServers({[key]:{[server]:original}})[0]?.transport;
  if(transport==='stdio' && (typeof original.command!=='string'||!original.command))
    throw Error('Missing server command');
  if(transport!=='stdio' && transport!=='http') throw Error('Unsupported MCP transport');
  if(transport==='http' && !['http','streamable-http',undefined].includes(original.type))
    throw Error('Legacy HTTP+SSE transport not supported');
  if(transport==='http') configuredHttpServer(path,server);
  const command=transport==='http'?'bridge':'proxy';
  if(policyFile)loadToolPolicy(policyFile,server);
  const {dir,file}=targetFile(path,server);
  if(existsSync(file))throw Error('Already installed; use uninstall before reinstall');
  if(dryRun) return {server,config:path,transport,command,changed:false,dryRun:true};
  const parent=join(dirname(path),'.faraday');
  for (const check of [parent,dir]) {
    if (existsSync(check) && (lstatSync(check).isSymbolicLink() || !lstatSync(check).isDirectory()))
      throw Error('Unsafe FARADAY backup directory');
  }
  mkdirSync(dir,{recursive:true,mode:0o700});
  if(process.platform==='win32'){
    // Secure both parent and target before creating any credential-bearing backup.
    protectWindowsAcl(parent);protectWindowsAcl(dir);
  }else chmodSync(dir,0o700);
  const proxy={command:nodePath,args:[binPath,command,'--config',file,'--server',server,'--db',resolve(db),...(policyFile?['--policy',resolve(policyFile)]:[])]};
  const source={ [key]:{[server]:original},_faradayInstall:{version:1,wrapper:proxy} };
  // Backup contains original launch command, arguments and possibly credentials.
  // It is never committed or printed; owners should protect their local files.
  writeFileSync(file,JSON.stringify(source,null,2)+'\n',{encoding:'utf8',flag:'wx',mode:0o600});
  try {
    if(process.platform==='win32')protectWindowsAcl(file);
    else chmodSync(file,0o600);
    json[key][server]=proxy;
    const mode=statSync(path).mode & 0o777;
    safeFile(path,JSON.stringify(json,null,2)+'\n',mode);
  } catch(e) { try {unlinkSync(file);}catch{} throw e; }
  return {server,transport,config:path,backup:file,db:resolve(db)};
}
export function uninstallProxy({configFile,server}) {
  if(!server||!configFile)throw Error('uninstall requires --config and --server');
  const path=resolve(configFile);
  if(lstatSync(path).isSymbolicLink()) throw Error('Refusing symlinked MCP configuration');
  const {file}=targetFile(path,server);
  if(!existsSync(file))throw Error('FARADAY backup not found');
  if(lstatSync(file).isSymbolicLink())throw Error('Unsafe backup symlink');
  if(process.platform==='win32'){
    verifyWindowsAcl(dirname(file));verifyWindowsAcl(file);
  }
  const current=JSON.parse(readFileSync(path,'utf8'));
  const previous=JSON.parse(readFileSync(file,'utf8'));
  const key=locate(previous,server);
  const activeKey=locate(current,server);
  if(key!==activeKey||!Array.isArray(current[key][server]?.args)
      ||!['proxy','bridge'].includes(current[key][server].args[1])
    ||current[key][server].args[3]!==file
    ||(Object.hasOwn(previous,'_faradayInstall')&&
      (previous._faradayInstall?.version!==1||!isDeepStrictEqual(previous._faradayInstall.wrapper,current[key][server])))) {
    throw Error('Config changed: refusing to overwrite; restore manually from private backup');
  }
  current[key][server]=previous[key][server];
  const mode=statSync(path).mode & 0o777;
  safeFile(path,JSON.stringify(current,null,2)+'\n',mode);
  unlinkSync(file);
  return {server,config:path};
}
