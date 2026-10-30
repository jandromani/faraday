#!/usr/bin/env node
/** Real PostgreSQL TTL fencing: independent contender workers, withheld
 * renewals, stale owner rejected after lease expires. No actual network cut.
 */
import assert from 'node:assert/strict';
import {Pool} from 'pg';
import {createNativePgLeaseCoordinator} from '../lib/native-pg-lease.js';
import {createNativePgFencedExecutor} from '../lib/native-pg-fencing.js';
import {PostgresFencedSyntheticStore} from '../lib/postgres-fenced-store.js';
const opts={host:'127.0.0.1',port:15432,database:'faraday',max:10,connectionTimeoutMillis:5000};
const control=new Pool({...opts,user:'faraday_controller',password:'faraday-r12-ctrl-test'});
const execute=new Pool({...opts,user:'faraday_executor',password:'faraday-r12-exec-test'});
const coordinator=createNativePgLeaseCoordinator({controllerPool:control});
const store=new PostgresFencedSyntheticStore({executeSql:createNativePgFencedExecutor({pool:execute})});
const body={tool:'pay_invoice',resource:'invoice:demo',action:'pay',
 args:{amount_cents:100,currency:'EUR',recipient:'supplier_demo'}};
const id=n=>'r13-expiring-lease-operation-'+String(n).padStart(5,'0');
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const start=performance.now();
try{
 const epochA=await coordinator.claim({owner:'gateway-a',ttlMs:650});
 assert.equal(epochA,'1');
 const other=await Promise.all(['gateway-b','gateway-c','gateway-d'].map(owner=>
  coordinator.claim({owner,ttlMs:650})));
 assert.deepEqual(other,[null,null,null],'only one lease owner may be active');
 assert.equal((await store.apply({...body,operationId:id(1),fenceOwner:'gateway-a',fenceEpoch:epochA})).http,200);
 // Simulate A losing its control-plane link: stop A heartbeats deliberately.
 await sleep(950);
 assert.equal((await store.apply({...body,operationId:id(2),fenceOwner:'gateway-a',fenceEpoch:epochA})).status,'fenced');
 const contender=await Promise.all(['gateway-b','gateway-c','gateway-d'].map(owner=>
  coordinator.claim({owner,ttlMs:650})));
 const winner=contender.map((epoch,index)=>({epoch,owner:['gateway-b','gateway-c','gateway-d'][index]}))
  .filter(x=>x.epoch!==null);
 assert.equal(winner.length,1,'exactly one owner must win after expiry');
 const {owner,epoch}=winner[0];
 assert.equal(epoch,'2');
 assert.equal((await store.apply({...body,operationId:id(3),fenceOwner:'gateway-a',fenceEpoch:epochA})).status,'fenced');
 const group=await Promise.all(Array.from({length:12},()=>store.apply({...body,
  operationId:id(4),fenceOwner:owner,fenceEpoch:epoch})));
 assert.ok(group.every(x=>x.http===200),'same authorized request must reconcile');
 assert.equal(group.filter(x=>x.duplicate===false).length,1);
 assert.equal(await store.count(),2);
 await assert.rejects(execute.query(
  "SELECT faraday_secure.claim_lease('invoice:demo','gateway-x',1000)"),/permission denied/i);
 await assert.rejects(control.query(
  "SELECT faraday_secure.apply_effect('invoice:demo','gateway-a',1,'r13-expiring-lease-operation-00007',repeat('a',64))"),/permission denied/i);
 await sleep(850);
 assert.equal((await store.apply({...body,operationId:id(5),fenceOwner:owner,fenceEpoch:epoch})).status,'fenced');
 const revived=await coordinator.claim({owner:'gateway-different',ttlMs:1500});
 assert.equal(revived,'3');
 assert.equal((await store.apply({...body,operationId:id(6),fenceOwner:'gateway-different',fenceEpoch:revived})).http,200);
 assert.equal(await store.count(),3);
 const elapsedMs=Math.round(performance.now()-start);
 console.log(JSON.stringify({kind:'faraday-r13-expiring-leases',result:'pass',
  evidence:{contendingOwners:3,electedAfterExpiry:1,epochs:[epochA,epoch,revived],
   syntheticEffects:3,parallelRetries:12,firstCommits:1,
   staleOwnerDenied:true,expiredOwnerDenied:true,privilegeSeparation:true,elapsedMs},
  limits:['Renewal stopped in one CI process, not real network partition',
   'manual operation requests after lease acquisition, not full automatic service failover',
   'one PostgreSQL failure domain','synthetic effects only']}));
}catch(error){console.error('R13 real lease test failed: '+String(error?.message||'unknown'));process.exitCode=1;}
finally{await Promise.allSettled([control.end(),execute.end()]);}
