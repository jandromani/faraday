import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fixture,AGENT,ARGS,TOOL} from '../lib/authority-fixture.js';
import {newIdentity} from '../lib/authority.js';
import {ExecutionJournal,verifyReceipt} from '../lib/pilot-receipts.js';
import {DurableSyntheticStore,createDurableSyntheticBackend} from '../lib/pilot-backend.js';
import {createSecurePilotGateway} from '../lib/pilot-mcp.js';
import {reconcileSyntheticOperation} from '../lib/pilot-reconcile.js';
const VERSION='2026-07-28';
const listen=server=>new Promise(ok=>server.listen(0,'127.0.0.1',()=>ok('http://127.0.0.1:'+server.address().port)));
const close=server=>new Promise(ok=>server.close(ok));
for(const [description,ambiguousResponse] of [
  ['corrupted response',()=>new Response('corrupted-response',{status:200})],
  ['server error',()=>new Response(JSON.stringify({error:'internal'}),{status:500})],
  ['inconsistent success',()=>new Response(JSON.stringify({status:'simulated',operationId:'other',requestHash:'other'}),{status:200})]
]) test(`${description} is reconciled using signed backend status without replaying the tool`,async t=>{
  const dir=mkdtempSync(join(tmpdir(),'faraday-reconcile-'));
  const f=fixture(dir),gatewayKey=newIdentity(),backendKey=newIdentity(),journal=new ExecutionJournal(join(dir,'journal.sqlite')),store=new DurableSyntheticStore(join(dir,'store.sqlite'));
  let gateway,backend;
  t.after(async()=>{if(gateway?.listening)await close(gateway);if(backend?.listening)await close(backend);f.close();journal.close();store.close();rmSync(dir,{recursive:true,force:true});});
  backend=createDurableSyntheticBackend({secret:f.backendSecret,store,attestationPrivatePem:backendKey.privatePem});
  const backendUrl=await listen(backend);
  gateway=createSecurePilotGateway({gate:f.gate,backendUrl:backendUrl+'/internal/execute',backendSecret:f.backendSecret,journal,receiptPrivatePem:gatewayKey.privatePem,backendPublicPem:backendKey.publicPem,
    fetchFn:async(url,options)=>{const response=await fetch(url,options);await response.arrayBuffer();return ambiguousResponse();}});
  const gatewayUrl=await listen(gateway);
  const msg={jsonrpc:'2.0',id:1,method:'tools/call',params:{name:TOOL,arguments:ARGS,_meta:{'io.modelcontextprotocol/protocolVersion':VERSION}}};
  const response=await fetch(gatewayUrl+'/mcp',{method:'POST',headers:{'content-type':'application/json','mcp-protocol-version':VERSION,'mcp-method':'tools/call','mcp-name':TOOL,
    'x-faraday-capability':f.capability,'x-faraday-proof':Buffer.from(JSON.stringify(f.proof)).toString('base64url')},body:JSON.stringify(msg)});
  assert.equal(response.status,503);assert.equal(store.count(),1);
  const opId=f.gate.ledger.db.prepare("SELECT key FROM consumed WHERE key LIKE 'cap:%'").get().key.slice(4);
  assert.equal(journal.get(opId).state,'upstream-uncertain');
  let contacted=false;
  await assert.rejects(reconcileSyntheticOperation({operationId:opId,journal,backendUrl:'http://backend.example/internal/execute',backendSecret:f.backendSecret,
    backendPublicPem:backendKey.publicPem,receiptPrivatePem:gatewayKey.privatePem,receiptPublicPem:gatewayKey.publicPem,fetchFn:()=>{contacted=true;}}),/invalid-backend-endpoint/);
  assert.equal(contacted,false);
  const result=await reconcileSyntheticOperation({operationId:opId,journal,backendUrl:backendUrl+'/internal/execute',backendSecret:f.backendSecret,
    backendPublicPem:backendKey.publicPem,receiptPrivatePem:gatewayKey.privatePem,receiptPublicPem:gatewayKey.publicPem});
  assert.equal(result.reconciled,true);assert.equal(result.executionRepeated,false);assert.equal(store.count(),1);
  assert.equal(journal.get(opId).state,'simulated');
  assert.equal(verifyReceipt({publicPem:gatewayKey.publicPem,backendPublicPem:backendKey.publicPem,receipt:result.receipt}).backendVerified,true);
  assert.throws(()=>journal.reconcile(opId,result.receipt),/not-reconcilable/);
});
