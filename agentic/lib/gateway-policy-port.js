/** Optional third-party policy port, NOT installed into the production gateway. */
import {createHash} from 'node:crypto';
const hash=v=>createHash('sha256').update(v).digest('hex').slice(0,24);
export function createFailClosedGatewayPolicyPort({authorize,timeoutMs=1000}={}){
 if(typeof authorize!=='function')throw Error('explicit policy backend required');
 if(!Number.isSafeInteger(timeoutMs)||timeoutMs<10||timeoutMs>10000)throw Error('invalid timeout');
 return async function evaluate({agent,method,resource}={}){
  if(![agent,method,resource].every(x=>typeof x==='string'&&x.length>0&&x.length<=512))return {allowed:false,reason:'invalid-context'};
  if(!['tools/call','tools/list'].includes(method))return {allowed:false,reason:'unsupported-method'};
  const snapshot=Object.freeze({version:1,subjectFingerprint:hash(agent),resourceFingerprint:hash(resource),method});
  let timer;
  try{
   const response=await Promise.race([
    Promise.resolve().then(()=>authorize(snapshot)),
    new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('policy-timeout')),timeoutMs);})
   ]);
   if(!response||typeof response!=='object'||response.decision!=='allow'&&response.decision!=='deny')return {allowed:false,reason:'invalid-verdict'};
   return {allowed:response.decision==='allow',reason:response.decision==='allow'?'explicit-allow':'external-deny'};
  }catch{return {allowed:false,reason:'external-unavailable'};}
  finally{clearTimeout(timer);}
 };
}
