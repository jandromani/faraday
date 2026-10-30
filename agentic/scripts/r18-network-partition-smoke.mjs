#!/usr/bin/env node
/** R18: actively disconnect & reconnect the DATABASE network of two independent
 * Docker worker containers while retaining a separate observation network.
 * Results are synthetic PostgreSQL effects. Never use real payments.
 */
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
const network='faraday-r18-dbnet';
const a='faraday-r18-a',b='faraday-r18-b';
const token=process.env.R18_LAB_TOKEN;
if(!token||token.length<20)throw Error('missing-lab-token');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function docker(...args){
 return new Promise((resolve,reject)=>{
  const child=spawn('docker',args,{stdio:['ignore','pipe','pipe']});
  let out='',err='';
  const timeout=setTimeout(()=>child.kill('SIGKILL'),15000);
  child.stdout.on('data',d=>{out+=d;if(out.length>65536)child.kill('SIGKILL');});
  child.stderr.on('data',d=>{err+=d;if(err.length>65536)child.kill('SIGKILL');});
  child.once('error',e=>{clearTimeout(timeout);reject(e);});
  child.once('close',code=>{clearTimeout(timeout);code===0?resolve(out.trim()):reject(Error('docker-failed:'+args.slice(0,2).join(',')));});
 });
}
const url=(name)=>'http://127.0.0.1:'+(name===a?17811:17812);
async function status(name){
 const r=await fetch(url(name)+'/status',{signal:AbortSignal.timeout(1200)});
 assert.equal(r.status,200);return r.json();
}
async function effect(name,operationId){
 const r=await fetch(url(name)+'/effect',{method:'POST',headers:{'content-type':'application/json','x-faraday-r18-lab':token},
  body:JSON.stringify({operationId}),signal:AbortSignal.timeout(3500)});
 return {http:r.status,...await r.json()};
}
async function until(predicate,maxMs=12500){
 const start=performance.now();
 while(performance.now()-start<maxMs){
  try{const v=await predicate();if(v)return {value:v,elapsedMs:Math.round(performance.now()-start)};}catch{}
  await sleep(180);
 }
 throw Error('condition-not-observed');
}
async function count(){
 const output=await docker('exec','faraday-r18-db','psql','-U','faraday','-d','faraday','-X','-At','-c',
  "SELECT count(*) FROM public.faraday_r5_effects WHERE scope='invoice:demo'");
 const n=Number(output);if(!Number.isSafeInteger(n))throw Error('bad-ledger-count');
 return n;
}
const op=n=>'r18-separated-nodes-synthetic-effect-'+String(n).padStart(5,'0');
const evidence={kind:'faraday-r18-real-network-partition',mode:'isolated-ci',network:'docker-bridge-disconnect'};
let detachedA=false,detachedB=false;
try{
 const initial=await until(async()=>{const s=await status(a);return s.active&&s.epoch?s:null;});
 const sA=initial.value,initialEpoch=BigInt(sA.epoch);
 const sB=(await until(async()=>await status(b))).value;
 assert.equal(sB.active,false,'B must not co-own the first live lease');
 assert.equal((await effect(a,op(1))).http,200);
 assert.equal(await count(),1);
 // Real network partition: node A loses its only route to PostgreSQL, but
 // observer network is not interrupted, so the effect probe still reaches A.
 await docker('network','disconnect',network,a);detachedA=true;
 await until(async()=>{const s=await status(a);return s.lastError&&!s.active?s:null;});
 const takeover=await until(async()=>{const s=await status(b);
  return s.active&&BigInt(s.epoch)>initialEpoch?s:null;},12000);
 evidence.aToBMs=takeover.elapsedMs;
 assert.equal((await effect(a,op(2))).http,503,'partitioned A must not report a committed effect');
 assert.equal((await effect(b,op(3))).http,200);
 assert.equal(await count(),2);
 await docker('network','connect',network,a);detachedA=false;
 await until(async()=>{const s=await status(a);return s.connected&&!s.active?s:null;});
 const old=await effect(a,op(4));
 assert.equal(old.http,409,'healed A must be fenced by database even with old epoch');
 assert.equal(old.status,'fenced');
 assert.equal(await count(),2);
 // Reverse the partition; first owner A can win a *fresh* epoch, never reuse
 // its former fencing token, even while B thinks it was previously leader.
 const secondEpoch=BigInt(takeover.value.epoch);
 await docker('network','disconnect',network,b);detachedB=true;
 const back=await until(async()=>{const s=await status(a);
  return s.active&&BigInt(s.epoch)>secondEpoch?s:null;},12500);
 evidence.bToAMs=back.elapsedMs;
 assert.equal((await effect(b,op(5))).http,503,'partitioned B cannot acknowledge an effect');
 assert.equal((await effect(a,op(6))).http,200);
 await docker('network','connect',network,b);detachedB=false;
 await until(async()=>{const s=await status(b);return s.connected&&!s.active?s:null;});
 assert.equal((await effect(b,op(7))).http,409,'recovered B old lease must remain fenced');
 assert.equal(await count(),3,'three synthetic commits only across both outages');
 const retry=await effect(a,op(6));
 assert.equal(retry.http,200);
 assert.equal(retry.duplicate,true,'retry must be idempotent');
 assert.equal(await count(),3);
 evidence.result='pass';
 evidence.nodes=2;
 evidence.physicalDatabaseNetworkCuts=2;
 evidence.syntheticCommittedEffects=3;
 evidence.staleOwnerPostHealDenied=true;
 evidence.epochs=[sA.epoch,takeover.value.epoch,back.value.epoch];
 evidence.idempotentAfterRecovery=true;
 evidence.limits=['Single PostgreSQL instance','Laboratory worker holds both DB roles, NOT production least-privilege',
   'No third-party MCP client or actual outside payment in this campaign',
   'Do not interpret observed failover latency as production RTO'];
 console.log(JSON.stringify(evidence));
}catch(e){console.error('R18 physical network isolation proof failed: '+String(e.message||'error'));process.exitCode=1;}
finally{
 if(detachedA)await docker('network','connect',network,a).catch(()=>{});
 if(detachedB)await docker('network','connect',network,b).catch(()=>{});
}
