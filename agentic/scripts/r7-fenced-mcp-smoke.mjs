#!/usr/bin/env node
/** Real FARADAY MCP gateway → backend → PostgreSQL reference integration.
 * Controllable synthetic effects; no payment, no automatic failover.
 */
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtempSync,mkdirSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fixture,AGENT,ARGS,TOOL,RESOURCE,ACTION} from '../lib/authority-fixture.js';
import {createIntent,createExecution,newIdentity} from '../lib/authority.js';
import {ExecutionJournal,verifyReceipt} from '../lib/pilot-receipts.js';
import {createSecurePilotGateway} from '../lib/pilot-mcp.js';
import {createDurableSyntheticBackend} from '../lib/pilot-backend.js';
import {PostgresFencedSyntheticStore} from '../lib/postgres-fenced-store.js';
import {R5_FENCING_SCHEMA,R5_TAKEOVER_SQL} from '../lib/postgres-fencing-protocol.js';
const container='faraday-r7-postgres';
async function run(command,args,input=''){
 return new Promise((resolve,reject)=>{
  const child=spawn(command,args,{stdio:['pipe','pipe','pipe']});
  let stdout='',size=0,settled=false;
  const timeout=setTimeout(()=>child.kill('SIGKILL'),20000);
  child.stdout.on('data',chunk=>{size+=chunk.length;stdout+=chunk.toString();if(size>65536)child.kill('SIGKILL');});
  child.stderr.on('data',chunk=>{size+=chunk.length;if(size>65536)child.kill('SIGKILL');});
  child.on('error',()=>{if(!settled){settled=true;clearTimeout(timeout);reject(Error('postgres-driver-unavailable'));}});
  child.on('close',code=>{if(!settled){settled=true;clearTimeout(timeout);
    code===0?resolve(stdout.trim()):reject(Error('postgres-command-failed'));}});
  child.stdin.on('error',()=>{});child.stdin.end(input);
 });
}
async function sql(query,params={}){
 const opts=[];
 for(const [key,val] of Object.entries(params)){
  if(!['scope','owner','epoch','operation','digest'].includes(key)||
     typeof val!=='string'||val.length>128||!/^[A-Za-z0-9:._-]+$/.test(val))throw Error('invalid-sql-param');
  opts.push('-v',key+'='+val);
 }
 return run('docker',['exec','-i',container,'psql','-U','faraday','-d','faraday','-X','-q','-A','-t',
  '-v','ON_ERROR_STOP=1',...opts,'-f','-'],query);
}
function fresh(f){
 const now=Math.floor(Date.now()/1000);
 const intent=createIntent({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,
  agentPrivatePem:f.agent.privatePem,now});
 const capability=f.iss.issue(intent);
 const proof=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,
  capability,agentPrivatePem:f.agent.privatePem,now});
 return {capability,proof};
}
const id=capability=>JSON.parse(Buffer.from(capability,'base64url').toString('utf8')).payload.jti;
const proto='2026-07-28';
async function request(url,{capability,proof},args=ARGS){
 const response=await fetch(url+'/mcp',{method:'POST',headers:{'content-type':'application/json',
  'mcp-protocol-version':proto,'mcp-method':'tools/call','mcp-name':'pay_invoice',
  'x-faraday-capability':capability,'x-faraday-proof':Buffer.from(JSON.stringify(proof)).toString('base64url')},
  body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{
   name:TOOL,arguments:args,_meta:{'io.modelcontextprotocol/protocolVersion':proto}}})});
 return {status:response.status,body:await response.json()};
}
const root=mkdtempSync(join(tmpdir(),'faraday-r7-e2e-'));
const servers=[],contexts=[],journals=[];
async function listen(s){await new Promise(resolve=>s.listen(0,'127.0.0.1',resolve));servers.push(s);
 return 'http://127.0.0.1:'+s.address().port;}
try{
 await sql(R5_FENCING_SCHEMA);
 const epochA=await sql(R5_TAKEOVER_SQL,{scope:'invoice:demo',owner:'gateway-a'});
 assert.match(epochA,/^[1-9][0-9]*$/);
 const aRoot=join(root,'a'),bRoot=join(root,'b');mkdirSync(aRoot);mkdirSync(bRoot);
 const a=fixture(aRoot),b=fixture(bRoot);contexts.push(a,b);
 const receipts=newIdentity(),backKey=newIdentity();
 const jA=new ExecutionJournal(join(aRoot,'journal.sqlite')),jB=new ExecutionJournal(join(bRoot,'journal.sqlite'));
 journals.push(jA,jB);
 const db=new PostgresFencedSyntheticStore({executeSql:sql});
 const backend=await listen(createDurableSyntheticBackend({store:db,
  gatewaySecrets:{'gateway-a':a.backendSecret,'gateway-b':b.backendSecret},
  attestationPrivatePem:backKey.privatePem}));
 const ga=await listen(createSecurePilotGateway({gate:a.gate,backendUrl:backend+'/internal/execute',
  backendSecret:a.backendSecret,backendPublicPem:backKey.publicPem,
  receiptPrivatePem:receipts.privatePem,journal:jA,
  fencingLease:{owner:'gateway-a',epoch:epochA}}));
 const validA=fresh(a),one=await request(ga,validA);
 assert.equal(one.status,200,'gateway A legitimate signed MCP operation denied');
 assert.equal(await db.count(),1);
 assert.equal(verifyReceipt({publicPem:receipts.publicPem,backendPublicPem:backKey.publicPem,
   receipt:one.body.result.structuredContent.receipt}).backendVerified,true);
 assert.equal((await request(ga,validA)).status,403);
 const epochB=await sql(R5_TAKEOVER_SQL,{scope:'invoice:demo',owner:'gateway-b'});
 assert.equal(BigInt(epochB),BigInt(epochA)+1n);
 const afterTakeover=fresh(a),stale=await request(ga,afterTakeover);
 assert.equal(stale.status,503,'stale owner must fail closed rather than acknowledge effect');
 assert.equal(jA.get(id(afterTakeover.capability)).state,'upstream-uncertain');
 assert.equal(await db.count(),1,'stale gateway applied an effect after fencing');
 const gb=await listen(createSecurePilotGateway({gate:b.gate,backendUrl:backend+'/internal/execute',
  backendSecret:b.backendSecret,backendPublicPem:backKey.publicPem,
  receiptPrivatePem:receipts.privatePem,journal:jB,
  fencingLease:{owner:'gateway-b',epoch:epochB}}));
 const validB=fresh(b),two=await request(gb,validB);
 assert.equal(two.status,200,'promoted gateway did not execute');
 assert.equal(verifyReceipt({publicPem:receipts.publicPem,backendPublicPem:backKey.publicPem,
  receipt:two.body.result.structuredContent.receipt}).backendVerified,true);
 assert.equal(await db.count(),2);
 const extraId='r7-concurrent-idempotency-00001';
 const privilegedBody={tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,
  operationId:extraId,fenceOwner:'gateway-b',fenceEpoch:epochB};
 const doBackend=async(body,secret=b.backendSecret)=>{
  const response=await fetch(backend+'/internal/execute',{method:'POST',headers:{
   'content-type':'application/json',authorization:'Bearer '+secret},body:JSON.stringify(body)});
  return {http:response.status,body:await response.json()};
 };
 const parallel=await Promise.all(Array.from({length:8},()=>doBackend(privilegedBody)));
 assert.ok(parallel.every(x=>x.http===200),'authorized duplicate retry must reconcile');
 assert.equal(parallel.filter(x=>x.body.duplicate===false).length,1,'exactly one first committed effect expected');
 assert.equal(await db.count(),3);
 assert.equal((await doBackend({...privilegedBody,fenceOwner:'gateway-a'})).http,403,
  'gateway credential must bind to owner');
 assert.equal((await doBackend({...privilegedBody,operationId:'r7-invalid-fence-operation-01',fenceEpoch:epochA})).http,409,
  'old epoch with current credentials must be refused');
 assert.equal((await doBackend({...privilegedBody,operationId:'r7-other-token-operation-01'},a.backendSecret)).http,403);
 const noCredential=await fetch(backend+'/internal/execute',{method:'POST',headers:{
  'content-type':'application/json'},body:JSON.stringify(privilegedBody)});
 assert.equal(noCredential.status,401);await noCredential.body?.cancel();
 assert.equal(await db.count(),3);
 console.log(JSON.stringify({kind:'faraday-r7-actual-mcp-postgres',result:'pass',
  measured:{syntheticCommittedEffects:3,concurrentBackendRetries:8,firstCommits:1,
   fencedOldGateway:true,verifiedReceipts:2,authorizedFailover:'operator-triggered'},
  limitations:['No automatic failover','No external bank/payment side effect','No multi-region HA',
   'backend psql via Docker is CI reference driver only','PostgreSQL single point of failure']}));
}catch(error){console.error('R7 protected MCP fencing integration failed: '+String(error?.message||'unknown'));process.exitCode=1;}
finally{
 for(const s of [...servers].reverse()){s.closeAllConnections?.();await new Promise(resolve=>s.close(resolve));}
 for(const j of journals)j.close();
 for(const f of contexts)f.close();
 rmSync(root,{recursive:true,force:true});
}
