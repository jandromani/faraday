import {lstatSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
export class ToolPolicy {
  constructor(doc,server){
    if(!obj(doc)||doc.version!==1||doc.mode!=='enforce'||!obj(doc.allowedTools)||
       Object.keys(doc).some(k=>!['version','mode','allowedTools','maxArgumentBytes'].includes(k)))
      throw Error('Unsupported FARADAY tool policy (expected enforce v1)');
    const list=doc.allowedTools[server];
    if(!Array.isArray(list)||list.length>1000||list.some(x=>typeof x!=='string'||!x||x.length>200))
      throw Error('Explicit allowlist required for selected server');
    const size=doc.maxArgumentBytes??8192;
    if(!Number.isSafeInteger(size)||size<32||size>131072)throw Error('Invalid argument limit');
    this.allowed=new Set(list);this.maxArgumentBytes=size;
  }
  decision(message){
    if(!obj(message)||message.jsonrpc!=='2.0')return {allowed:false};
    if(message.method!=='tools/call')return {allowed:true};
    const name=message.params?.name;
    if(typeof name!=='string'||!this.allowed.has(name))return {allowed:false};
    try{
      if(Buffer.byteLength(JSON.stringify(message.params?.arguments??{}))>this.maxArgumentBytes)
        return {allowed:false};
    }catch{return {allowed:false};}
    return {allowed:true};
  }
}
export function loadToolPolicy(path,server){
  if(!path)return null;
  const file=resolve(path),st=lstatSync(file);
  if(!st.isFile()||st.isSymbolicLink()||st.size>131072)throw Error('Unsafe FARADAY policy file');
  return new ToolPolicy(JSON.parse(readFileSync(file,'utf8')),server);
}
export function denialReply(message){
  if(!obj(message)||!Object.hasOwn(message,'id'))return null;
  const id=message.id;
  if(!(id===null||typeof id==='number'||typeof id==='string'))return null;
  return JSON.stringify({jsonrpc:'2.0',id,error:{code:-32003,message:'FARADAY policy denied tool execution'}})+'\n';
}
