#!/usr/bin/env node
/** Official PostgreSQL + pg client, SCRAM auth and executor/controller separation. */
import assert from 'node:assert/strict';
import {Pool} from 'pg';
import {createNativePgFencedExecutor,createNativePgPromotion} from '../lib/native-pg-fencing.js';
import {PostgresFencedSyntheticStore} from '../lib/postgres-fenced-store.js';
const host='127.0.0.1',port=15432,database='faraday',scope='invoice:demo';
const opts={host,port,database,max:8,connectionTimeoutMillis:5000};
const executor=new Pool({...opts,user:'faraday_executor',password:'faraday-r12-exec-test'});
const controller=new Pool({...opts,user:'faraday_controller',password:'faraday-r12-ctrl-test'});
const store=new PostgresFencedSyntheticStore({executeSql:createNativePgFencedExecutor({pool:executor})});
const promote=createNativePgPromotion({pool:controller});
const expectedBody={tool:'pay_invoice',resource:'invoice:demo',action:'pay',
 args:{amount_cents:100,currency:'EUR',recipient:'supplier_demo'}};
const operation=i=>'r12-native-fenced-operation-'+String(i).padStart(5,'0');
try{
 const [ex,ct]=await Promise.all([executor.query('SELECT current_user AS role'),controller.query('SELECT current_user AS role')]);
 assert.equal(ex.rows[0].role,'faraday_executor');
 assert.equal(ct.rows[0].role,'faraday_controller');
 await assert.rejects(executor.query('SELECT * FROM public.faraday_r5_effects'),/permission denied/i);
 await assert.rejects(executor.query("UPDATE public.faraday_r5_leases SET epoch=300"),/permission denied/i);
 await assert.rejects(executor.query("SELECT faraday_secure.promote('invoice:demo','gateway-a')"),/permission denied/i);
 await assert.rejects(controller.query("SELECT faraday_secure.apply_effect('invoice:demo','gateway-a',1,'r12-native-fenced-operation-00000',repeat('a',64))"),/permission denied/i);
 const epochA=await promote({scope,owner:'gateway-a'});
 assert.equal(epochA,'1');
 const one=await store.apply({...expectedBody,operationId:operation(1),fenceOwner:'gateway-a',fenceEpoch:epochA});
 assert.equal(one.http,200);assert.equal(one.duplicate,false);
 const repeat=await store.apply({...expectedBody,operationId:operation(1),fenceOwner:'gateway-a',fenceEpoch:epochA});
 assert.equal(repeat.http,200);assert.equal(repeat.duplicate,true);
 assert.equal((await store.apply({...expectedBody,operationId:operation(1),args:{...expectedBody.args,amount_cents:101},fenceOwner:'gateway-a',fenceEpoch:epochA})).http,409);
 assert.equal(await store.count(),1);
 const epochB=await promote({scope,owner:'gateway-b'});
 assert.equal(epochB,'2');
 assert.equal((await store.apply({...expectedBody,operationId:operation(2),fenceOwner:'gateway-a',fenceEpoch:epochA})).http,409);
 const parallel=await Promise.all(Array.from({length:16},()=>store.apply({...expectedBody,
   operationId:operation(3),fenceOwner:'gateway-b',fenceEpoch:epochB})));
 assert.ok(parallel.every(x=>x.http===200),'all authentic idempotent retries must reconcile');
 assert.equal(parallel.filter(x=>x.duplicate===false).length,1);
 assert.equal(await store.count(),2);
 const state=await store.get(operation(3));
 assert.equal(state.request_hash,parallel[0].requestHash);
 assert.equal(state.status,'simulated');
 assert.equal((await store.apply({...expectedBody,operationId:operation(4),
   fenceOwner:'gateway-b',fenceEpoch:epochA})).http,409);
 assert.equal(await store.count(),2);
 await assert.rejects(createNativePgFencedExecutor({pool:executor})('SELECT * FROM pg_authid',{}),/unsupported-native-pg-statement/);
 await assert.rejects(promote({scope,owner:"gateway-a';DROP TABLE pg_authid;--"}),/invalid-promotion/);
 console.log(JSON.stringify({kind:'faraday-r12-native-pg',result:'pass',
  controls:['real-native-pg-driver','SCRAM-authenticated-independent-roles',
   'executor-cannot-promote','controller-cannot-apply','executor-cannot-read-base-table',
   'unique-idempotency','stale-owner-denial','16-concurrent-retries-one-effect',
   'payload-hash-reconciliation','parameterized-queries-only'],
  effects:2,retries:16,
  limits:['single PostgreSQL instance','CI transport uses loopback TCP (production helper requires TLS CA)',
   'synthetic ledger effects','no external payment or HA certification']}));
}catch(err){console.error('R12 native PG integration failed: '+String(err?.message||'unknown'));process.exitCode=1;}
finally{await Promise.allSettled([executor.end(),controller.end()]);}
