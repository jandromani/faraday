/** Guard configured MCP HTTP egress with DNS validation pinned to actual socket. */
import {lookup as dnsLookup} from 'node:dns/promises';
import {isIP} from 'node:net';
import http from 'node:http';
import https from 'node:https';
const strip=s=>s.replace(/^\[/,'').replace(/\]$/,'').replace(/\.$/,'').toLowerCase();
export function forbiddenIp(input){
  let ip=strip(input);
  if(ip.startsWith('::ffff:')){
    const tail=ip.slice(7);
    if(isIP(tail)===4)ip=tail;
    else if(/^[0-9a-f]{1,4}:[0-9a-f]{1,4}$/i.test(tail)){
      const words=tail.split(':').map(x=>parseInt(x,16));
      ip=String(words[0]>>8)+'.'+String(words[0]&255)+'.'+String(words[1]>>8)+'.'+String(words[1]&255);
    }
  }
  if(isIP(ip)===4){
    const [a,b,c]=ip.split('.').map(Number);
    return a===0||a===10||a===127||a>=224||a===169&&b===254||
      a===172&&b>=16&&b<=31||a===192&&b===168||a===100&&b>=64&&b<=127||
      a===192&&b===0||a===198&&b>=18&&b<=19||a===192&&b===0&&c===2||
      a===198&&b===51&&c===100||a===203&&b===0&&c===113;
  }
  if(isIP(ip)===6){
    if(ip==='::1'||ip==='::')return true;
    const first=parseInt(ip.split(':')[0]||'0',16);
    return (first&0xfe00)===0xfc00||(first&0xffc0)===0xfe80||
      (first&0xff00)===0xff00||first<0x2000||ip.startsWith('2001:db8:');
  }
  return true;
}
export function validatedMcpUrl(value){
  if(typeof value!=='string'||!value||value.length>4096)throw Error('Invalid configured MCP target');
  let url;try{url=new URL(value);}catch{throw Error('Invalid configured MCP target');}
  if(url.username||url.password||url.hash)throw Error('URL-embedded credentials and fragments forbidden');
  if([...url.searchParams.keys()].some(k=>/(?:token|key|secret|password|authorization|credential)/i.test(k)))
    throw Error('Secrets in URL query forbidden');
  const host=strip(url.hostname),loopback=['localhost','127.0.0.1','::1'].includes(host);
  if(url.protocol!=='https:'&&!(url.protocol==='http:'&&loopback))
    throw Error('Only HTTPS remote MCP endpoints or loopback HTTP endpoints are permitted');
  if(!url.hostname||/\s/.test(value))throw Error('Invalid target hostname');
  if(isIP(host)&&forbiddenIp(host)&&!loopback)throw Error('Non-loopback private/reserved destination forbidden');
  if(host.endsWith('.localhost')||host==='localhost.localdomain')throw Error('Unapproved local hostname');
  return url;
}
export async function pinnedAddress(input,{resolver=dnsLookup}={}){
  const url=validatedMcpUrl(String(input)),host=strip(url.hostname);
  if(isIP(host))return {address:host,family:isIP(host)};
  if(host==='localhost')return {address:'127.0.0.1',family:4};
  const answers=await resolver(host,{all:true,verbatim:true});
  if(!Array.isArray(answers)||!answers.length||answers.length>64)throw Error('Cannot validate DNS destination');
  if(answers.some(x=>!x||!isIP(x.address)||forbiddenIp(x.address)))
    throw Error('Destination resolves to a private or reserved IP');
  return {address:answers[0].address,family:answers[0].family||isIP(answers[0].address)};
}
export async function secureMcpFetch(target,options={},security={}){
  const url=validatedMcpUrl(String(target)),pinned=await pinnedAddress(url,security);
  const module=url.protocol==='https:'?https:http, maxBytes=security.maxBytes??8*1024*1024;
  return await new Promise((resolve,reject)=>{
    const req=module.request(url,{
      method:options.method||'POST',headers:options.headers||{},
      signal:options.signal,maxHeaderSize:16384,
      lookup:(_host,opt,cb)=>{
        if(typeof opt==='function'){cb=opt;opt={};}
        if(opt?.all)cb(null,[pinned]);else cb(null,pinned.address,pinned.family);
      },
    },res=>{
      let total=0,claimed=false;
      const body=(async function*(){
        try{
          for await(const chunk of res){
            total+=chunk.length;
            if(total>maxBytes){res.destroy();throw Error('MCP upstream response exceeds size limit');}
            yield chunk;
          }
        }finally{res.destroy();}
      })();
      resolve({status:res.statusCode,ok:res.statusCode>=200&&res.statusCode<300,
        headers:{get:name=>res.headers[String(name).toLowerCase()]||null},
        body,
        async text(){if(claimed)throw Error('Response already consumed');claimed=true;
          const parts=[];for await(const chunk of body)parts.push(chunk);
          return Buffer.concat(parts).toString('utf8');},
        async discard(){for await(const chunk of body){}},
      });
    });
    req.on('error',reject);
    if(options.signal?.aborted){req.destroy();return;}
    req.end(options.body??undefined);
  });
}
