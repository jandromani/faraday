import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {createPrivateKey,sign} from 'node:crypto';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {newIdentity,createExecution,createIntent,canonical} from '../lib/authority.js';
import {fixture,AGENT,TOOL,RESOURCE,ACTION,ARGS} from '../lib/authority-fixture.js';
import {signApproval,verifyApprovals,encodeApprovals,decodeApprovals} from '../lib/approvals.js';
import {LocalSentinel} from '../lib/sentinel.js';
import {LocalBudget} from '../lib/budget.js';
import {ExecutionJournal} from '../lib/pilot-receipts.js';
import {DurableSyntheticStore,createDurableSyntheticBackend} from '../lib/pilot-backend.js';
import {createSecurePilotGateway} from '../lib/pilot-mcp.js';
const dir=t=>{const d=mkdtempSync(join(tmpdir(),'faraday-operator-')),resources=[];t.after(()=>{for(const resource of resources)resource.close();rmSync(d,{recursive:true,force:true});});return {d,resources};};
function approvals(){
 const a=newIdentity(),b=newIdentity(),scope={capability:'capability-1234567890123456789',agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS};
 const bundle=[signApproval({...scope,approver:'finance',privatePem:a.privatePem}),signApproval({...scope,approver:'security',privatePem:b.privatePem})];
 const keys={finance:{publicPem:a.publicPem,role:'finance'},security:{publicPem:b.publicPem,role:'security'}};
 return {a,b,bundle,scope,keys};
}
test('E18 two independent signatures and roles are required',()=>{
 const a=approvals();assert.equal(verifyApprovals({...a.scope,bundle:a.bundle,approverKeys:a.keys,quorum:2,requiredRoles:['finance','security']}).approved,true);
 assert.deepEqual(decodeApprovals(encodeApprovals(a.bundle)),a.bundle);
 assert.throws(()=>verifyApprovals({...a.scope,bundle:a.bundle.slice(0,1),approverKeys:a.keys,quorum:2}));
 assert.throws(()=>verifyApprovals({...a.scope,bundle:[a.bundle[0],a.bundle[0]],approverKeys:a.keys,quorum:2}));
});
test('E18 approval schema rejects separator collisions',()=>{
 const a=approvals(),claims={...a.bundle[0].claims};
 delete claims.action;delete claims.agent;claims['action|agent']='synthetic';
 assert.throws(()=>verifyApprovals({...a.scope,bundle:[{...a.bundle[0],claims},a.bundle[1]],approverKeys:a.keys,quorum:2}),/invalid-approval/);
});
test('E18 two approver aliases sharing a public key do not satisfy quorum',()=>{
 const a=approvals();
 const duplicate=signApproval({...a.scope,approver:'security',privatePem:a.a.privatePem});
 const keys={...a.keys,security:{publicPem:a.a.publicPem,role:'security'}};
 assert.throws(()=>verifyApprovals({...a.scope,bundle:[a.bundle[0],duplicate],approverKeys:keys,quorum:2,requiredRoles:['finance','security']}),/duplicate-approver-key/);
});
test('E18 consent cannot authorize another agent, resource, capability or arguments',()=>{
 const a=approvals();for(const change of [{agent:'bad'},{resource:'other'},{capability:a.scope.capability+'x'},{args:{...ARGS,amount_cents:1}}])
  assert.throws(()=>verifyApprovals({...a.scope,...change,bundle:a.bundle,approverKeys:a.keys,quorum:2}));
});
test('E18 forged signature and expiry are rejected',()=>{
 const a=approvals();assert.throws(()=>verifyApprovals({...a.scope,bundle:a.bundle,approverKeys:a.keys,quorum:2,now:Math.floor(Date.now()/1000)+500}));
 const fake=signApproval({...a.scope,approver:'finance',privatePem:newIdentity().privatePem});
 assert.throws(()=>verifyApprovals({...a.scope,bundle:[fake,a.bundle[1]],approverKeys:a.keys,quorum:2}));
});
test('E18 invalid approval clock fails closed',()=>{
 const a=approvals();
 for(const now of [NaN,Infinity,1.5,'0'])assert.throws(()=>verifyApprovals({...a.scope,bundle:a.bundle,approverKeys:a.keys,quorum:2,now}),/approvals-required/);
});
test('E18 signed approval cannot expire before it was issued',()=>{
 const a=approvals(),now=Math.floor(Date.now()/1000),claims={...a.bundle[0].claims,issuedAt:now+2,expiresAt:now+1};
 const signature=sign(null,Buffer.concat([Buffer.from('FARADAY-APPROVAL-0.96\0'),canonical(claims)]),createPrivateKey(a.a.privatePem)).toString('base64url');
 assert.throws(()=>verifyApprovals({...a.scope,bundle:[{claims,signature}],approverKeys:a.keys,quorum:1,now}),/approval-mismatch-or-expired/);
 assert.throws(()=>signApproval({...a.scope,approver:'finance',privatePem:a.a.privatePem,now:Number.MAX_SAFE_INTEGER,ttl:1}),/invalid-approval-request/);
});
test('E19 emergency stop persists across two SQLite connections',t=>{
 const {d,resources}=dir(t),path=join(d,'s.sqlite'),a=new LocalSentinel(path);resources.push(a);
 a.stop(true);const b=new LocalSentinel(path);resources.push(b);
 assert.equal(b.isBlocked('dummy'),true);b.stop(false);
 assert.equal(a.isBlocked('dummy'),false);assert.equal(a.verifyChain().verified,true);
});
test('E19 stop changes roll back when audit storage fails',t=>{
 const {d,resources}=dir(t),sentinel=new LocalSentinel(join(d,'s.sqlite'));resources.push(sentinel);
 sentinel.stop(true);
 sentinel.db.exec("CREATE TRIGGER reject_control BEFORE INSERT ON events WHEN NEW.kind='control' BEGIN SELECT RAISE(FAIL,'audit unavailable'); END");
 assert.throws(()=>sentinel.stop(false),/sentinel-storage-unavailable/);
 assert.equal(sentinel.isStopped(),true);assert.equal(sentinel.verifyChain().verified,true);
});
test('E19 denial quarantine and hash-chain mutation detection',t=>{
 const {d,resources}=dir(t),path=join(d,'s.sqlite');let now=10000;const a=new LocalSentinel(path,{threshold:2,now:()=>now,cooldownMs:1000});resources.push(a);
 a.record('deny','IP-1','invalid-proof');a.record('deny','IP-1','invalid-proof');
 assert.equal(a.isBlocked('IP-1'),true);assert.equal(a.isBlocked('IP-2'),false);now=12000;assert.equal(a.isBlocked('IP-1'),false);
 a.db.exec("UPDATE events SET reason='forged' WHERE seq=1");assert.equal(a.verifyChain().verified,false);
});
test('E19 quarantine activation and evidence roll back together',t=>{
 const {d,resources}=dir(t),sentinel=new LocalSentinel(join(d,'s.sqlite'),{threshold:2,now:()=>10000});resources.push(sentinel);
 sentinel.record('deny','IP-1','invalid-proof');
 sentinel.db.exec("CREATE TRIGGER reject_quarantine BEFORE INSERT ON events WHEN NEW.kind='quarantine' BEGIN SELECT RAISE(FAIL,'audit unavailable'); END");
 assert.throws(()=>sentinel.record('deny','IP-1','invalid-proof'),/sentinel-storage-unavailable/);
 assert.equal(sentinel.isBlocked('IP-1'),false);assert.equal(sentinel.status().events,1);
 sentinel.db.exec('DROP TRIGGER reject_quarantine');sentinel.record('deny','IP-1','invalid-proof');
 assert.equal(sentinel.isBlocked('IP-1'),true);
 assert.equal(sentinel.db.prepare("SELECT count(*) AS n FROM events WHERE kind='quarantine' AND reason='denial-threshold'").get().n,1);
 assert.equal(sentinel.verifyChain().verified,true);
});
test('E19 alert outbox persists and retries after a failed delivery',async t=>{
 const {d,resources}=dir(t),path=join(d,'s.sqlite'),first=new LocalSentinel(path,{threshold:2,now:()=>10000});resources.push(first);
 first.record('deny','IP-1','invalid-proof');first.record('deny','IP-1','invalid-proof');
 const second=new LocalSentinel(path,{now:()=>10000});resources.push(second);
 assert.equal(second.pendingAlerts().length,1);
 const failed=await second.deliverAlerts({url:'https://alerts.example.test/incident',fetchFn:async()=>({ok:false})});
 assert.equal(failed.delivered,0);assert.equal(failed.pending,true);
 let request;const delivered=await second.deliverAlerts({url:'https://alerts.example.test/incident',fetchFn:async(endpoint,options)=>{request={endpoint,options};return {ok:true};}});
 assert.equal(delivered.delivered,1);assert.equal(delivered.pending,false);
 const payload=JSON.parse(request.options.body);assert.equal(payload.event.kind,'quarantine');assert.equal(payload.event.reason,'denial-threshold');
 assert.equal(JSON.stringify(payload).includes('IP-1'),false);assert.equal(request.options.redirect,'error');
 await assert.rejects(second.deliverAlerts({url:'http://alerts.example.test',fetchFn:async()=>({ok:true})}),/invalid-alert-endpoint/);
});
test('E19 alert outbox failure rolls back stop and quarantine',t=>{
 const {d,resources}=dir(t),sentinel=new LocalSentinel(join(d,'s.sqlite'),{threshold:2,now:()=>10000});resources.push(sentinel);
 sentinel.record('deny','IP-1','invalid-proof');
 sentinel.db.exec("CREATE TRIGGER reject_outbox BEFORE INSERT ON alert_outbox BEGIN SELECT RAISE(FAIL,'outbox unavailable'); END");
 assert.throws(()=>sentinel.stop(true),/sentinel-storage-unavailable/);assert.equal(sentinel.isStopped(),false);
 assert.throws(()=>sentinel.record('deny','IP-1','invalid-proof'),/sentinel-storage-unavailable/);
 assert.equal(sentinel.isBlocked('IP-1'),false);assert.equal(sentinel.status().events,1);
});
test('E19 accepted alerts remain retryable if delivery acknowledgement cannot be stored',async t=>{
 const {d,resources}=dir(t),sentinel=new LocalSentinel(join(d,'s.sqlite'));resources.push(sentinel);sentinel.stop(true);
 sentinel.db.exec("CREATE TRIGGER reject_delivery BEFORE UPDATE ON alert_outbox BEGIN SELECT RAISE(FAIL,'outbox unavailable'); END");
 const observed=[],fetchFn=async(_endpoint,options)=>{observed.push(JSON.parse(options.body).event.event_hash);return {ok:true};};
 await assert.rejects(sentinel.deliverAlerts({url:'https://alerts.example.test',fetchFn}),/sentinel-storage-unavailable/);
 assert.equal(sentinel.pendingAlerts().length,1);sentinel.db.exec('DROP TRIGGER reject_delivery');
 assert.equal((await sentinel.deliverAlerts({url:'https://alerts.example.test',fetchFn})).delivered,1);
 assert.deepEqual(observed,[observed[0],observed[0]]);
});
test('E19 supervised local recovery requires the current intact chain',t=>{
 const {d,resources}=dir(t),path=join(d,'s.sqlite'),first=new LocalSentinel(path),second=new LocalSentinel(path);resources.push(first,second);
 first.stop(true);const stale=first.verifyChain().head;
 second.record('allow','IP-1','checked');
 assert.throws(()=>first.recover({expectedHead:stale,operator:'responder',reason:'reviewed'}),/sentinel-evidence-changed/);
 assert.equal(first.isStopped(),true);
 const head=first.verifyChain().head;first.recover({expectedHead:head,operator:'responder',reason:'reviewed'});
 assert.equal(second.isStopped(),false);assert.equal(second.verifyChain().verified,true);
 const event=second.db.prepare("SELECT reason FROM events ORDER BY seq DESC LIMIT 1").get();assert.equal(event.reason,'recovery:reviewed');
 assert.equal(second.pendingAlerts().length,2);
});
test('E19 invalid and rolled-back clocks fail closed for quarantine',t=>{
 const {d,resources}=dir(t);let now=10000;
 const sentinel=new LocalSentinel(join(d,'s.sqlite'),{threshold:2,now:()=>now});resources.push(sentinel);
 sentinel.record('deny','IP-1','invalid-proof');sentinel.record('deny','IP-1','invalid-proof');
 for(const value of [NaN,Infinity,-1,9999]){now=value;assert.throws(()=>sentinel.isBlocked('IP-1'),/invalid-sentinel-clock/);}
 now=10000;assert.equal(sentinel.isBlocked('IP-1'),true);
});
test('E19 altered chain blocks delivery and guarded recovery',async t=>{
 const {d,resources}=dir(t),sentinel=new LocalSentinel(join(d,'s.sqlite'));resources.push(sentinel);sentinel.stop(true);
 const head=sentinel.verifyChain().head;sentinel.db.exec("UPDATE events SET reason='forged' WHERE seq=1");
 let called=false;await assert.rejects(sentinel.deliverAlerts({url:'https://alerts.example.test',fetchFn:async()=>{called=true;return {ok:true};}}),/sentinel-evidence-changed/);
 assert.equal(called,false);assert.throws(()=>sentinel.recover({expectedHead:head,operator:'responder',reason:'reviewed'}),/sentinel-evidence-changed/);assert.equal(sentinel.isStopped(),true);
});
test('E19 CLI exposes pending alerts and guarded recovery',t=>{
 const {d,resources}=dir(t),path=join(d,'s.sqlite'),sentinel=new LocalSentinel(path);resources.push(sentinel);sentinel.stop(true);
 const command=args=>spawnSync(process.execPath,['bin/faraday.js','sentinel',...args,'--db',path],{encoding:'utf8',timeout:10000});
 const alerts=command(['alerts']);assert.equal(alerts.status,0,alerts.stderr);assert.equal(JSON.parse(alerts.stdout).alerts.length,1);
 const recovery=command(['recover','--head',sentinel.verifyChain().head,'--operator','responder','--reason','reviewed']);
 assert.equal(recovery.status,0,recovery.stderr);assert.equal(JSON.parse(recovery.stdout).stopped,false);
});
test('E19 multiple local processes serialize incident events in one SQLite database',async t=>{
 const {d,resources}=dir(t),path=join(d,'s.sqlite'),sentinel=new LocalSentinel(path,{threshold:2});resources.push(sentinel);
 const moduleUrl=pathToFileURL(join(process.cwd(),'lib','sentinel.js')).href;
 const script=`import {LocalSentinel} from ${JSON.stringify(moduleUrl)};
let input='';for await(const chunk of process.stdin)input+=chunk;
const sentinel=new LocalSentinel(input,{threshold:2});try{sentinel.record('deny','synthetic-source','invalid-proof');}finally{sentinel.close();}`;
 await Promise.all(Array.from({length:4},()=>new Promise((resolve,reject)=>{
  const child=spawn(process.execPath,['--no-warnings','--input-type=module','-e',script],{stdio:['pipe','ignore','pipe']});let errors='';
  child.stderr.on('data',chunk=>errors+=chunk);child.on('error',reject);child.on('close',code=>code===0?resolve():reject(Error(errors||`exit ${code}`)));child.stdin.end(path);
 })));
 assert.equal(sentinel.isBlocked('synthetic-source'),true);
 assert.equal(sentinel.db.prepare("SELECT count(*) AS n FROM events WHERE kind='deny'").get().n,4);
 assert.ok(sentinel.pendingAlerts().length>=1);assert.equal(sentinel.verifyChain().verified,true);
});
test('E17 budgets persist and fail closed for exhausted or unknown agents',t=>{
 const {d,resources}=dir(t),path=join(d,'q.sqlite'),limits={[AGENT]:{maxCalls:1,windowMs:60000}};
 const a=new LocalBudget(path,{limits});resources.push(a);assert.equal(a.consume(AGENT).remaining,0);
 const b=new LocalBudget(path,{limits});resources.push(b);assert.throws(()=>b.consume(AGENT),/budget-exhausted/);
 assert.throws(()=>b.consume('unknown'),/no-budget-policy/);
 assert.throws(()=>b.consume('constructor'),/no-budget-policy/);
});
test('E17 gateway rejects budget configuration without a database',t=>{
 const {d}=dir(t),config=join(d,'gateway.json');
 for(const name of ['budgets','organizationBudgets','agentOrganizations']){
  writeFileSync(config,JSON.stringify({[name]:{}}));
  const result=spawnSync(process.execPath,['bin/faraday-pilot-gateway.js'],{env:{...process.env,FARADAY_PILOT_CONFIG:config},encoding:'utf8',timeout:10000});
  assert.notEqual(result.status,0);assert.match(result.stderr,/budgetDb required/);
 }
});
test('E17 clock rollback cannot reopen an earlier unused window',t=>{
 const {d,resources}=dir(t),path=join(d,'q.sqlite'),limits={[AGENT]:{maxCalls:1,windowMs:60000}};let time=120000;
 const first=new LocalBudget(path,{limits,now:()=>time});resources.push(first);first.consume(AGENT);
 const second=new LocalBudget(path,{limits,now:()=>time});resources.push(second);
 time=60000;assert.throws(()=>second.consume(AGENT),/budget-clock-rollback/);
 time=180000;assert.equal(second.consume(AGENT).remaining,0);
});
test('E17 local organization quota is atomic across agents and rolls back denied use',t=>{
 const {d,resources}=dir(t),path=join(d,'org.sqlite'),limits={agentA:{maxCalls:4,windowMs:60000},agentB:{maxCalls:4,windowMs:60000}},organizationLimits={orgA:{maxCalls:2,windowMs:60000}},agentOrganizations={agentA:'orgA',agentB:'orgA'};
 const first=new LocalBudget(path,{limits,organizationLimits,agentOrganizations,now:()=>120000}),second=new LocalBudget(path,{limits,organizationLimits,agentOrganizations,now:()=>120000});resources.push(first,second);
 assert.equal(first.consume('agentA').organizationRemaining,1);assert.equal(second.consume('agentB').organizationRemaining,0);
 assert.throws(()=>first.consume('agentA'),/organization-budget-exhausted/);
 assert.equal(first.db.prepare('SELECT calls FROM usage WHERE agent=?').get('agentA').calls,1);
 assert.throws(()=>new LocalBudget(join(d,'invalid.sqlite'),{limits,organizationLimits,agentOrganizations:{agentA:'orgA'}}),/invalid-budget-organizations/);
});
test('E17 organization clock prevents rollback across different agents',t=>{
 const {d,resources}=dir(t);let time=120000;
 const budget=new LocalBudget(join(d,'org-clock.sqlite'),{limits:{agentA:{maxCalls:2,windowMs:60000},agentB:{maxCalls:2,windowMs:60000}},organizationLimits:{orgA:{maxCalls:2,windowMs:60000}},agentOrganizations:{agentA:'orgA',agentB:'orgA'},now:()=>time});resources.push(budget);
 budget.consume('agentA');time=60000;assert.throws(()=>budget.consume('agentB'),/budget-clock-rollback/);
 assert.equal(budget.db.prepare('SELECT count(*) AS n FROM usage WHERE agent=?').get('agentB').n,0);
 time=120000;assert.equal(budget.consume('agentB').organizationRemaining,0);
});
test('E17 organization quota is shared by processes using different agents',async t=>{
 const {d,resources}=dir(t),path=join(d,'org-process.sqlite'),limits={agentA:{maxCalls:6,windowMs:60000},agentB:{maxCalls:6,windowMs:60000}},organizationLimits={orgA:{maxCalls:3,windowMs:60000}},agentOrganizations={agentA:'orgA',agentB:'orgA'};
 const budget=new LocalBudget(path,{limits,organizationLimits,agentOrganizations});resources.push(budget);
 const moduleUrl=pathToFileURL(join(process.cwd(),'lib','budget.js')).href;
 const script=`import {LocalBudget} from ${JSON.stringify(moduleUrl)};
let input='';for await(const chunk of process.stdin)input+=chunk;
const config=JSON.parse(input),budget=new LocalBudget(config.path,{limits:config.limits,organizationLimits:config.organizationLimits,agentOrganizations:config.agentOrganizations,now:()=>1800000000000});
try{process.stdout.write(JSON.stringify(budget.consume(config.agent)));}catch(error){process.stdout.write(JSON.stringify({error:error.code}));}finally{budget.close();}`;
 const results=await Promise.all(Array.from({length:6},(_,index)=>new Promise((resolve,reject)=>{
  const child=spawn(process.execPath,['--no-warnings','--input-type=module','-e',script],{stdio:['pipe','pipe','pipe']});
  let output='',errors='';child.stdout.on('data',chunk=>output+=chunk);child.stderr.on('data',chunk=>errors+=chunk);
  child.on('error',reject);child.on('close',code=>{if(code!==0)return reject(Error(errors||`exit ${code}`));try{resolve(JSON.parse(output));}catch(error){reject(error);}});
  child.stdin.end(JSON.stringify({path,limits,organizationLimits,agentOrganizations,agent:index%2?'agentA':'agentB'}));
 })));
 assert.deepEqual(results.filter(result=>result.allowed).map(result=>result.organizationRemaining).sort(),[0,1,2]);
 assert.equal(results.filter(result=>result.error==='organization-budget-exhausted').length,3);
 assert.equal(budget.db.prepare('SELECT sum(calls) AS n FROM usage').get().n,3);
});
test('E17 concurrent processes share a local quota and report atomic remaining values',async t=>{
 const {d,resources}=dir(t),path=join(d,'quota.sqlite'),limits={[AGENT]:{maxCalls:3,windowMs:60000}};
 const budget=new LocalBudget(path,{limits});resources.push(budget);
 const moduleUrl=pathToFileURL(join(process.cwd(),'lib','budget.js')).href;
 const script=`import {LocalBudget} from ${JSON.stringify(moduleUrl)};
let input='';for await(const chunk of process.stdin)input+=chunk;
const config=JSON.parse(input),budget=new LocalBudget(config.path,{limits:config.limits,now:()=>1800000000000});
try{process.stdout.write(JSON.stringify(budget.consume(config.agent)));}catch(error){process.stdout.write(JSON.stringify({error:error.code}));}finally{budget.close();}`;
 const config=JSON.stringify({path,limits,agent:AGENT});
 const results=await Promise.all(Array.from({length:6},()=>new Promise((resolve,reject)=>{
  const child=spawn(process.execPath,['--no-warnings','--input-type=module','-e',script],{stdio:['pipe','pipe','pipe']});
  let output='',errors='';child.stdout.on('data',chunk=>output+=chunk);child.stderr.on('data',chunk=>errors+=chunk);
  child.on('error',reject);child.on('close',code=>{if(code!==0)return reject(Error(errors||`exit ${code}`));try{resolve(JSON.parse(output));}catch(error){reject(error);}});child.stdin.end(config);
 })));
 assert.deepEqual(results.filter(result=>result.allowed).map(result=>result.remaining).sort(),[0,1,2]);
 assert.equal(results.filter(result=>result.error==='budget-exhausted').length,3);
});
async function listen(t,server){await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));return 'http://127.0.0.1:'+server.address().port;}
async function gatewaySetup(t,{agentAsApprover=false}={}){
 const {d:root,resources}=dir(t),f=fixture(root),receiptKey=newIdentity(),backendKey=newIdentity(),a=agentAsApprover?f.agent:newIdentity(),b=newIdentity();
 const journal=new ExecutionJournal(join(root,'j.sqlite')),store=new DurableSyntheticStore(join(root,'b.sqlite'));
 const sentinel=new LocalSentinel(join(root,'s.sqlite'),{threshold:2}),budget=new LocalBudget(join(root,'q.sqlite'),{limits:{[AGENT]:{maxCalls:1,windowMs:60000}}});
 resources.push(f,journal,store,sentinel,budget);
 const backend=createDurableSyntheticBackend({secret:f.backendSecret,store,attestationPrivatePem:backendKey.privatePem});
 const bk=await listen(t,backend);
 const approvalConfig={approverKeys:{finance:{publicPem:a.publicPem,role:'finance'},security:{publicPem:b.publicPem,role:'security'}},quorum:2,requiredRoles:['finance','security']};
 const server=createSecurePilotGateway({gate:f.gate,journal,sentinel,budget,approvalConfig,receiptPrivatePem:receiptKey.privatePem,backendPublicPem:backendKey.publicPem,
 backendUrl:bk+'/internal/execute',backendSecret:f.backendSecret});
 const url=await listen(t,server);
 const bundle=(capability)=>[signApproval({capability,agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,approver:'finance',privatePem:a.privatePem}),
 signApproval({capability,agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,approver:'security',privatePem:b.privatePem})];
 async function call(capability=f.capability,proof=f.proof,withApproval=true){
  const body={jsonrpc:'2.0',id:1,method:'tools/call',params:{name:TOOL,arguments:ARGS,_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28'}}};
  const headers={'content-type':'application/json','mcp-protocol-version':'2026-07-28','mcp-method':'tools/call','mcp-name':TOOL,
   'x-faraday-capability':capability,'x-faraday-proof':Buffer.from(JSON.stringify(proof)).toString('base64url')};
  if(withApproval)headers['x-faraday-approvals']=encodeApprovals(bundle(capability));
  return (await fetch(url+'/mcp',{method:'POST',headers,body:JSON.stringify(body)})).status;
 }
 return {f,store,sentinel,journal,approvalConfig,call};
}
test('E18/E19/E17 integrated: no approval denied, signed consent executes, replay blocked',async t=>{
 const x=await gatewaySetup(t);
 assert.equal(await x.call(x.f.capability,x.f.proof,false),403);
 assert.equal(x.store.count(),0);
 assert.equal(await x.call(),200);
 assert.equal(x.store.count(),1);
 const operationId=x.f.gatewayLedger.db.prepare("SELECT key FROM consumed WHERE key LIKE 'cap:%'").get().key.slice(4),evidence=x.journal.getApprovalEvidence(operationId);
 const verified=verifyApprovals({bundle:evidence.bundle,approverKeys:x.approvalConfig.approverKeys,quorum:2,requiredRoles:['finance','security'],capability:x.f.capability,agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS});
 assert.deepEqual(verified.approvers,['finance','security']);assert.equal(verified.approvalDigest,evidence.approvalDigest);
 assert.equal(await x.call(),403);
});
test('E18 approval evidence storage failure prevents execution and rolls back reservation',async t=>{
 const x=await gatewaySetup(t);
 x.journal.db.exec("CREATE TRIGGER reject_approval BEFORE INSERT ON approval_evidence BEGIN SELECT RAISE(FAIL,'unavailable'); END");
 assert.equal(await x.call(),403);assert.equal(x.store.count(),0);
 assert.equal(x.journal.db.prepare('SELECT count(*) AS n FROM executions').get().n,0);
 assert.equal(x.journal.db.prepare('SELECT count(*) AS n FROM approval_evidence').get().n,0);
});
test('E18 agent key cannot also approve its own operation',async t=>{
 const x=await gatewaySetup(t,{agentAsApprover:true});
 assert.equal(await x.call(),403);assert.equal(x.store.count(),0);
 assert.equal(x.f.gatewayLedger.db.prepare('SELECT count(*) AS n FROM consumed').get().n,0);
 assert.equal(x.journal.db.prepare('SELECT count(*) AS n FROM approval_evidence').get().n,0);
});
test('E19 integrated: emergency stop blocks correctly approved operation before side effect',async t=>{
 const x=await gatewaySetup(t);x.sentinel.stop(true);
 assert.equal(await x.call(),403);assert.equal(x.store.count(),0);
 x.sentinel.stop(false);
 assert.equal(await x.call(),200);assert.equal(x.store.count(),1);
});
test('E19 repeated gateway denials quarantine the source before execution',async t=>{
 const x=await gatewaySetup(t);
 assert.equal(await x.call(x.f.capability,x.f.proof,false),403);assert.equal(await x.call(x.f.capability,x.f.proof,false),403);
 assert.equal(await x.call(),403);assert.equal(x.store.count(),0);
 assert.equal(x.f.gatewayLedger.db.prepare('SELECT count(*) AS n FROM consumed').get().n,0);
 assert.equal(x.sentinel.pendingAlerts().some(event=>event.kind==='quarantine'),true);
});
test('E17 integrated: second signed capability cannot exceed fixed call budget',async t=>{
 const x=await gatewaySetup(t);assert.equal(await x.call(),200);
 const intent=createIntent({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,agentPrivatePem:x.f.agent.privatePem});
 const second=x.f.iss.issue(intent);
 const proof=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,capability:second,agentPrivatePem:x.f.agent.privatePem});
 assert.equal(await x.call(second,proof),403);assert.equal(x.store.count(),1);
});
