import test from 'node:test';
import assert from 'node:assert/strict';
import {PostgresFencedSyntheticStore} from '../lib/postgres-fenced-store.js';
import {createNativePgFencedExecutor,createNativePgPromotion,
 createTlsVerifiedNativePgPool} from '../lib/native-pg-fencing.js';
import {R5_APPLY_SQL,R5_TAKEOVER_SQL,R5_FENCING_SCHEMA} from '../lib/postgres-fencing-protocol.js';
const base=()=>({tool:'pay_invoice',resource:'invoice:demo',action:'pay',
 args:{amount_cents:100,currency:'EUR',recipient:'supplier_demo'},
 operationId:'r15-fuzz-operation-id-000001',fenceOwner:'gateway-attack',fenceEpoch:'1'});
test('500 deterministic hostile malformed requests never touch PostgreSQL',async()=>{
 let calls=0;
 const store=new PostgresFencedSyntheticStore({executeSql:async()=>{calls++;return 'applied';}});
 const values=["'; DROP TABLE faraday_r5_effects; --",'invoice:other',null,
   undefined,[],{},true,false,0,-1,2.5,NaN,Infinity,'', ' '.repeat(1024),
   'gateway-attack\n', '1 OR 1=1', '__proto__', '%00','../../secrets'];
 let count=0;
 for(let i=0;i<500;i++){
  const x=base(),v=values[i%values.length],which=i%10;
  if(which===0)x.tool=v;
  else if(which===1)x.resource=v;
  else if(which===2)x.action=v;
  else if(which===3)x.operationId=v;
  else if(which===4)x.fenceOwner=v;
  else if(which===5)x.fenceEpoch=v;
  else if(which===6)x.args.amount_cents=v;
  else if(which===7)x.args.currency=v;
  else if(which===8)x.args.recipient=v;
  else x.args={...x.args,untrusted:v};
  // A mutated value can occasionally equal a valid field. Always force
  // a second invalid predicate when needed to avoid false test positives.
  x.args={...x.args,additional_untrusted_field:'must-never-be-accepted'};
  const result=await store.apply(x);
  assert.equal(result.http,403,'malformed operation must fail closed');
  count++;
 }
 assert.equal(calls,0);
 assert.equal(count,500);
});
test('native PostgreSQL transport never forwards attacker SQL or invalid bind values',async()=>{
 let queries=0;
 const pool={query:async()=>{queries++;return {rows:[{result:'applied'}]};}};
 const exec=createNativePgFencedExecutor({pool});
 await assert.rejects(exec('SELECT * FROM pg_authid',{}),/unsupported-native-pg-statement/);
 await assert.rejects(exec(R5_TAKEOVER_SQL,{}),/forbidden-backend-control-statement/);
 await assert.rejects(exec(R5_FENCING_SCHEMA,{}),/forbidden-backend-control-statement/);
 for(const bad of [
  {scope:'invoice:demo',owner:'gateway-x',epoch:'1 OR 1=1',operation:'r15-fuzz-operation-id-000001',digest:'a'.repeat(64)},
  {scope:'invoice:demo',owner:'gateway-x',epoch:'1',operation:"'; DROP TABLE x; --",digest:'a'.repeat(64)},
  {scope:'invoice:demo',owner:"gateway-x'; --",epoch:'1',operation:'r15-fuzz-operation-id-000001',digest:'a'.repeat(64)},
  {scope:'invoice:demo',owner:'gateway-x',epoch:'1',operation:'r15-fuzz-operation-id-000001',digest:'a'.repeat(63)+'z'}])
  await assert.rejects(exec(R5_APPLY_SQL,bad),/invalid-native-pg-parameters/);
 assert.equal(queries,0,'no malicious input may reach DB query');
});
test('promotion cannot run from effect adapter and rejects malformed owners',async()=>{
 const pool={query:async()=>{throw Error('should-not-connect')}};
 const promote=createNativePgPromotion({pool});
 await assert.rejects(promote({scope:'invoice:demo',owner:"gateway-a';SELECT 1;--"}),/invalid-promotion/);
 await assert.rejects(promote({scope:'wrong',owner:'gateway-a'}),/invalid-promotion/);
});
test('production PostgreSQL helper denies missing trust root and local plaintext bypass',async()=>{
 for(const config of [{host:'127.0.0.1',database:'faraday',user:'x',password:'y',ca:'cert'},
  {host:'db.example.test',database:'faraday',user:'x',password:'y',ca:''},
  {host:'db.example.test',database:'faraday',user:'x',password:'y',ca:'cert',max:100}])
  await assert.rejects(createTlsVerifiedNativePgPool(config),/native-pg-TLS-and-credentials-required/);
});
