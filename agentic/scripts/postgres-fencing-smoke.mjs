#!/usr/bin/env node
/** R5: two distinct Node worker processes contend over real PostgreSQL.
 * Proof is a disposable integration environment, not automatic failover in production.
 */
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {R5_FENCING_SCHEMA,R5_TAKEOVER_SQL,R5_APPLY_SQL,R5_COUNT_SQL} from '../lib/postgres-fencing-protocol.js';
const container='faraday-r5-postgres';
const here=fileURLToPath(import.meta.url);
const check=(value,pattern)=>typeof value==='string'&&pattern.test(value);
async function command(cmd,args,input=''){
 return new Promise((resolve,reject)=>{
  const child=spawn(cmd,args,{stdio:['pipe','pipe','pipe'],windowsHide:true});
  let stdout='',stderr='',size=0;
  const deadline=setTimeout(()=>child.kill('SIGKILL'),20000);
  child.stdout.on('data',x=>{size+=x.length;if(size>65536)child.kill('SIGKILL');stdout+=x.toString();});
  child.stderr.on('data',x=>{size+=x.length;if(size>65536)child.kill('SIGKILL');stderr+=x.toString();});
  child.on('error',e=>{clearTimeout(deadline);reject(e);});
  child.on('close',code=>{clearTimeout(deadline);if(code!==0)reject(Error('postgres-integration-command-failed'));else resolve(stdout.trim());});
  child.stdin.on('error',()=>{});child.stdin.end(input);
 });
}
async function sql(query,params={}){
 const opts=[];
 for(const [key,value] of Object.entries(params)){
  if(!['scope','owner','epoch','operation','digest'].includes(key)||typeof value!=='string'||value.length>128||
     !/^[A-Za-z0-9:._-]+$/.test(value))throw Error('invalid-fencing-variable');
  opts.push('-v',key+'='+value);
 }
 return command('docker',['exec','-i',container,'psql','-U','faraday','-d','faraday','-X','-q','-A','-t',
  '-v','ON_ERROR_STOP=1',...opts,'-f','-'],query);
}
async function apply(owner,epoch,operation,digest){
 if(!check(owner,/^[a-z][a-z0-9-]{0,30}$/)||!check(operation,/^op-[a-z0-9-]{1,40}$/)||
    !check(digest,/^[a-f0-9]{64}$/)||!check(epoch,/^[1-9][0-9]{0,15}$/))throw Error('invalid-fencing-request');
 return sql(R5_APPLY_SQL,{scope:'invoice:demo',owner,epoch,operation,digest});
}
async function worker(owner,epoch,operation,digest){
 const out=await command(process.execPath,[here,'--worker',owner,epoch,operation,digest]);
 const result=out.trim();
 if(!['applied','duplicate','fenced','conflict'].includes(result))throw Error('invalid-worker-result');
 return result;
}
if(process.argv[2]==='--worker'){
 try{const x=await apply(...process.argv.slice(3,7));process.stdout.write(x+'\n');}
 catch{process.stderr.write('fencing-worker-denied\n');process.exitCode=2;}
}else{
 try{
  await sql(R5_FENCING_SCHEMA);
  const epochA=await sql(R5_TAKEOVER_SQL,{scope:'invoice:demo',owner:'gateway-a'});
  assert.match(epochA,/^[1-9][0-9]*$/);
  const digestA=createHash('sha256').update('operation-a').digest('hex');
  const digestB=createHash('sha256').update('operation-b').digest('hex');
  const digestOther=createHash('sha256').update('changed-payload').digest('hex');
  assert.equal(await worker('gateway-a',epochA,'op-first',digestA),'applied');
  assert.equal(await worker('gateway-a',epochA,'op-first',digestA),'duplicate');
  assert.equal(await worker('gateway-a',epochA,'op-first',digestOther),'conflict');
  // An operator promotes gateway B. The epoch is monotonically advanced by the DB.
  const epochB=await sql(R5_TAKEOVER_SQL,{scope:'invoice:demo',owner:'gateway-b'});
  assert.equal(BigInt(epochB),BigInt(epochA)+1n);
  assert.equal(await worker('gateway-a',epochA,'op-stale',digestB),'fenced');
  assert.equal(await worker('gateway-b',epochA,'op-stale',digestB),'fenced');
  const parallel=await Promise.all(Array.from({length:8},()=>worker('gateway-b',epochB,'op-second',digestB)));
  assert.equal(parallel.filter(x=>x==='applied').length,1,'concurrent workers must commit exactly one synthetic effect');
  assert.ok(parallel.every(x=>['applied','duplicate','conflict'].includes(x)),'unknown outcome');
  assert.equal(await worker('gateway-b',epochB,'op-second',digestB),'duplicate');
  assert.equal(await worker('gateway-b',epochB,'op-second',digestOther),'conflict');
  assert.equal(await sql(R5_COUNT_SQL,{scope:'invoice:demo'}),'2');
  // Crash/restart demonstration: a fresh process cannot resurrect the fenced owner.
  assert.equal(await worker('gateway-a',epochA,'op-third',digestA),'fenced');
  const epochC=await sql(R5_TAKEOVER_SQL,{scope:'invoice:demo',owner:'gateway-c'});
  assert.equal(await worker('gateway-b',epochB,'op-third',digestA),'fenced');
  assert.equal(await worker('gateway-c',epochC,'op-second',digestB),'duplicate');
  assert.equal(await sql(R5_COUNT_SQL,{scope:'invoice:demo'}),'2');
  console.log(JSON.stringify({kind:'faraday-r5-postgres-fencing',result:'pass',
   evidence:{independentProcesses:true,sharedPostgres:true,epochs:[epochA,epochB,epochC],
    simulatedEffects:2,concurrentWorkers:8,committedSecondEffect:parallel.filter(x=>x==='applied').length,
    staleEpochDenied:true,conflictingPayloadDenied:true,restartReplayDenied:true},
   limitations:['operator-triggered failover only','synthetic effects stored in PostgreSQL',
    'no production network partition or tenant-isolation attestation','not an R3 enterprise pass']}));
 }catch(e){console.error('R5 PostgreSQL fencing proof failed: '+String(e?.message||'unknown'));process.exitCode=1;}
}
