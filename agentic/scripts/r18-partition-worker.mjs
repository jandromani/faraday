#!/usr/bin/env node
/** R18 disposable, NON-PRODUCTION lab worker: one independent container per instance.
 * It deliberately holds an executor and controller DB credential in ONE CI process
 * to make failure injection reproducible. This is NOT an acceptable production
 * least-privilege architecture.
 */
import http from 'node:http';
import {Pool} from 'pg';
import {createNativePgLeaseCoordinator} from '../lib/native-pg-lease.js';
import {createNativePgFencedExecutor} from '../lib/native-pg-fencing.js';
import {PostgresFencedSyntheticStore} from '../lib/postgres-fenced-store.js';
const owner=process.argv[2];
if(!/^gateway-r18-[ab]$/.test(owner))throw Error('invalid-lab-owner');
const db={host:'faraday-r18-db',port:5432,database:'faraday',connectionTimeoutMillis:400,
 idleTimeoutMillis:750,max:3};
const controller=new Pool({...db,user:'faraday_controller',password:process.env.R18_CONTROLLER_PASSWORD});
const executor=new Pool({...db,user:'faraday_executor',password:process.env.R18_EXECUTOR_PASSWORD});
const coordinator=createNativePgLeaseCoordinator({controllerPool:controller});
const store=new PostgresFencedSyntheticStore({executeSql:createNativePgFencedExecutor({pool:executor})});
const ttlMs=1000;
let epoch=null,active=false,connected=false,heartbeatCount=0,lastError=false,lastErrorCode='none',busy=false;
const heartbeat=async()=>{
 if(busy)return;busy=true;
 try{
  const result=await coordinator.claim({owner,ttlMs});
  connected=true;lastError=false;heartbeatCount++;
  if(result!==null){epoch=result;active=true;}
  else active=false;
 }catch(e){
  lastErrorCode=typeof e?.code==='string'&&/^[A-Z0-9_]{2,32}$/.test(e.code)?e.code:'connection-failed';
  // Never assume local leadership after losing DB connectivity.
  connected=false;active=false;lastError=true;
 }finally{busy=false;}
};
await heartbeat();
const interval=setInterval(heartbeat,200);
const reply=(res,status,body)=>{
 const data=Buffer.from(JSON.stringify(body));
 res.writeHead(status,{'content-type':'application/json','content-length':data.length,'cache-control':'no-store'});
 res.end(data);
};
const server=http.createServer(async(req,res)=>{
 if(req.method==='GET'&&req.url==='/status')
  return reply(res,200,{owner,epoch,active,connected,heartbeatCount,lastError,lastErrorCode});
 if(req.method!=='POST'||req.url!=='/effect')return reply(res,404,{error:'unknown-endpoint'});
 if(req.headers['x-faraday-r18-lab']!==process.env.R18_LAB_TOKEN)
  return reply(res,401,{error:'lab-token-required'});
 let body;
 try{
  const chunks=[];let size=0;
  for await(const buf of req){size+=buf.length;if(size>4096)throw Error('oversize');chunks.push(buf);}
  body=JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if(!body||typeof body.operationId!=='string'||!/^[A-Za-z0-9_-]{20,80}$/.test(body.operationId))
   throw Error('bad-operation');
 }catch{return reply(res,400,{error:'malformed'});}
 // This endpoint deliberately sends the previously granted epoch after a
 // partition to test the DB's stale-owner refusal independently of the
 // caller's in-memory active flag. It applies synthetic effects only.
 if(epoch===null)return reply(res,409,{status:'never-leader'});
 const result=await store.apply({tool:'pay_invoice',resource:'invoice:demo',action:'pay',
  args:{amount_cents:100,currency:'EUR',recipient:'supplier_demo'},
  operationId:body.operationId,fenceOwner:owner,fenceEpoch:epoch});
 return reply(res,result.http,{status:result.status,duplicate:result.duplicate??false});
});
server.listen(7080,'0.0.0.0');
async function finish(){
 clearInterval(interval);server.closeAllConnections();
 await new Promise(resolve=>server.close(resolve));
 await Promise.allSettled([controller.end(),executor.end()]);
}
process.on('SIGTERM',()=>{finish().then(()=>process.exit(0)).catch(()=>process.exit(1));});
