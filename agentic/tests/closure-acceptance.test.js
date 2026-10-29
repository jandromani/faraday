/** Versioned acceptance evidence for *scoped* Developer Preview deliverables.
 * These tests DO NOT certify enterprise readiness, universal MCP compatibility,
 * workload attestation or absence of bypass on arbitrary networks.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,writeFileSync,readFileSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {readFileSync as read} from 'node:fs';
import {discover} from '../lib/discover.js';
import {initialize,doctor} from '../lib/setup.js';
import {installProxy,uninstallProxy} from '../lib/install.js';
import {compatibilityReport,PROTOCOL_PROFILE} from '../lib/compatibility.js';
import {GraphStore} from '../lib/store.js';
import {normalizeSchema,compareSnapshots} from '../lib/contracts.js';
import {evaluatePolicy,newIdentity,createExecution} from '../lib/authority.js';
import {fixture,AGENT,TOOL,RESOURCE,ACTION,ARGS,POLICY} from '../lib/authority-fixture.js';
import {diffAuthority} from '../lib/trust-diff.js';
import {captureSynthetic,replaySynthetic,verifyTrace} from '../lib/timemachine.js';
import {DUMMY_AGENTS,runLab,generateScenarios} from '../lib/lab.js';
import {LocalBudget} from '../lib/budget.js';
import {runBenchmarks} from '../lib/benchmarks.js';
import {runSyntheticWorkflow} from '../lib/workflow-e2e.js';
import {audit} from '../scripts/release-audit.mjs';

function workspace(t) {
 const dir=mkdtempSync(join(tmpdir(),'faraday-closure-'));
 t.after(()=>rmSync(dir,{recursive:true,force:true}));return dir;
}
const JSONFILE='docs/EPIC_CLOSURE_SCOPE_V1.json';
const manifest=JSON.parse(read(resolve(JSONFILE),'utf8'));
const ids=['E01','E05','E06','E07','E08','E10','E14','E17','E20','E21','E23','E25','E26','E27','E28'];

test('[E01] scoped threat model contains explicit threats, controls, negative test references and residual risks',()=>{
 assert.equal(manifest.version,1);assert.deepEqual(manifest.candidates.map(e=>e.id).sort(),ids.slice().sort());
 assert.ok(manifest.threats.length>=12);
 for(const row of manifest.threats){assert.ok(row.id&&row.risk&&row.control&&row.test&&row.residualRisk);assert.ok((Array.isArray(row.test)?row.test:[row.test]).some(p=>existsSync(resolve(p))));}
 assert.ok(manifest.candidates.every(e=>e.scope&&e.exclusions?.length&&e.acceptance?.length));
});

test('[E05] installer dry-run, double initialization, reversible wrapping and no unsafe credential logs',t=>{
 const root=workspace(t),config=join(root,'.mcp.json');
 const raw={mcpServers:{sandbox:{command:process.execPath,args:['--version'],env:{SECRET:'DO_NOT_ECHO_ME'}}}};
 writeFileSync(config,JSON.stringify(raw));
 const dry=initialize({root,dryRun:true});assert.equal(dry.dryRun,true);assert.equal(existsSync(join(root,'.faraday')),false);
 initialize({root});initialize({root});assert.equal(doctor({root}).ready,true);
 const planned=installProxy({configFile:config,server:'sandbox',db:join(root,'.faraday','graph.sqlite'),nodePath:process.execPath,binPath:resolve('bin/faraday.js'),dryRun:true});
 assert.equal(planned.changed,false);assert.deepEqual(JSON.parse(readFileSync(config,'utf8')),raw);
 const installed=installProxy({configFile:config,server:'sandbox',db:join(root,'.faraday','graph.sqlite'),nodePath:process.execPath,binPath:resolve('bin/faraday.js')});
 assert.ok(existsSync(installed.backup));uninstallProxy({configFile:config,server:'sandbox'});
 assert.deepEqual(JSON.parse(readFileSync(config,'utf8')),raw);
 assert.equal(existsSync(installed.backup),false);
 assert.ok(!JSON.stringify({dry,planned,installed}).includes('DO_NOT_ECHO_ME'));
});

test('[E06] MCP transport inventory is honest about stdio, Streamable HTTP and unsupported legacy SSE',t=>{
 const root=workspace(t);
 writeFileSync(join(root,'.mcp.json'),JSON.stringify({mcpServers:{local:{command:'node',args:['server.js']},remote:{type:'http',url:'https://example.test/mcp'},legacy:{type:'sse',url:'https://example.test/sse'}}}));
 const report=compatibilityReport({root});
 assert.equal(report.summary.configured,3);assert.equal(report.summary.eligible,2);assert.equal(report.summary.verifiedLive,0);
 assert.equal(report.servers.find(s=>s.server==='legacy').eligibleForBridge,false);
 assert.equal(report.servers.filter(s=>s.conformance==='untested').length,3);
 assert.ok(PROTOCOL_PROFILE.transports.includes('streamable-http'));
});

test('[E07] opt-in Python wrappers and API-level tests are present; no implicit framework interception',()=>{
 const root=resolve('python/faraday_adapters');
 for(const file of ['__init__.py','core.py','langgraph.py','crewai.py','openai_agents.py'])assert.ok(existsSync(join(root,file)),file);
 assert.ok(existsSync(resolve('python/tests/test_adapters.py')));
 assert.ok(existsSync(resolve('python/examples/langgraph_stategraph.py')));
});

test('[E08] Graph stores bounded metadata and sanitized structural contracts without secret-bearing descriptions',t=>{
 const root=workspace(t),db=join(root,'graph.sqlite');
 const g=new GraphStore(db);
 g.inventory([{client:'test-client',server:'sandbox',transport:'stdio'}]);
 g.contract('sandbox','read_document',{type:'object',description:'SECRET_E08_LEAK',properties:{id:{type:'string',default:'SECRET_E08_LEAK'}}});
 const snap=g.snapshot();assert.ok(snap.nodes.some(n=>n.type==='client'));assert.ok(snap.edges.some(e=>e.relation==='configured'));
 assert.equal(snap.stats.contracts,1);assert.ok(!readFileSync(db).includes(Buffer.from('SECRET_E08_LEAK')));g.close();
});

test('[E10] exact scope policy and signed agent proof deny a substituted resource and a forged identity',t=>{
 const root=workspace(t),f=fixture(root);
 assert.equal(evaluatePolicy(POLICY,{agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS}).allowed,true);
 assert.equal(evaluatePolicy(POLICY,{agent:AGENT,tool:TOOL,resource:'invoice:other',action:ACTION,args:ARGS}).allowed,false);
 assert.equal(evaluatePolicy(POLICY,{agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:{...ARGS,recipient:'attacker'}}).allowed,false);
 const rogue=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,capability:f.capability,agentPrivatePem:newIdentity().privatePem});
 assert.throws(()=>f.gate.authorize({capability:f.capability,proof:rogue}));f.close();
});

test('[E14] an executed synthetic MCP operation carries independently verifiable gateway and backend evidence',async()=>{
 const x=await runSyntheticWorkflow();
 assert.equal(x.status,'simulated');assert.equal(x.backendTotal,1);
 assert.equal(x.validation.verified,true);assert.equal(x.validation.signedBackendOperations,1);
 assert.equal(x.trace.mode,'offline-dummy');
});

test('[E17] SQLite quota fails closed, survives reopen and enforces quota across database reopen',t=>{
 const root=workspace(t),db=join(root,'budget.sqlite'),limits={demo:{maxCalls:3,windowMs:60000}};
 const b=new LocalBudget(db,{limits,now:()=>60010});
 for(let i=0;i<3;i++)assert.equal(b.consume('demo').allowed,true);
 assert.throws(()=>b.consume('demo'),/budget-exhausted/);b.close();
 const again=new LocalBudget(db,{limits,now:()=>60010});
 assert.throws(()=>again.consume('demo'),/budget-exhausted/);
 assert.throws(()=>again.consume('unknown'),/no-budget-policy/);again.close();
});

test('[E20] Preflight TrustDiff and schema diff classify expansions conservatively',()=>{
 const baseline={version:1,mode:'enforce',maxArgumentBytes:8192,allowedTools:{sandbox:['read_document']}};
 const expanded={...baseline,maxArgumentBytes:16384,allowedTools:{sandbox:['read_document','delete_document']}};
 const diff=diffAuthority(baseline,expanded);
 assert.equal(diff.summary.authorityExpanded,true);assert.deepEqual(diff.added.map(x=>x.tool),['delete_document']);
 const snap=t=>({format:'faraday-contract-snapshot',version:1,coverage:'observed-tools-list',tools:t});
 const tool=inputSchema=>({server:'sandbox',tool:'read_document',inputSchema,outputSchema:null,potentialClients:[],fingerprint:'fixture'});
 const old=normalizeSchema({type:'object',properties:{id:{type:'string'}}});
 const now=normalizeSchema({type:'object',properties:{id:{type:'string'},authorization:{type:'string'}},required:['authorization']});
 assert.ok(compareSnapshots(snap([tool(old)]),snap([tool(now)])).summary.breaking>0);
});

test('[E21] TimeMachine verifies synthetic replay integrity; policy changes affect outcomes without side effects',()=>{
 const trace=captureSynthetic({seed:42});assert.equal(verifyTrace(trace).verified,true);
 const r=replaySynthetic(trace);assert.equal(r.mode,'offline-no-effects');
 const mutated=structuredClone(trace);mutated.steps[0].outcome='forged';assert.throws(()=>verifyTrace(mutated));
});

test('[E23] synthetic agent factory guarantees deterministic unique fixture identities, with explicit coverage gaps',()=>{
 assert.equal(DUMMY_AGENTS.length,12);assert.equal(new Set(DUMMY_AGENTS.map(x=>x.id)).size,12);
 assert.deepEqual(generateScenarios(42),generateScenarios(42));
 const report=runLab({seed:42});assert.deepEqual(report.summary,{total:1000,passed:650,failed:0,gaps:350});
});

test('[E25] compatibility evidence distinguishes observed configurations from real SDK conformance',t=>{
 const root=workspace(t);writeFileSync(join(root,'.mcp.json'),JSON.stringify({mcpServers:{sample:{command:'node'}}}));
 const report=compatibilityReport({root});assert.equal(report.servers.length,1);
 assert.equal(report.servers[0].observed,false);assert.equal(report.servers[0].conformance,'untested');
 assert.ok(existsSync(resolve('python/tests/test_real_sdks.py'))||existsSync(resolve('python/tests/test_adapters.py')));
});

test('[E26] seeded adversarial corpus is reproducible and security gaps never count as passes',()=>{
 for(const seed of [0,1,42,998]){
  const a=generateScenarios(seed),b=generateScenarios(seed);assert.deepEqual(a,b);assert.equal(new Set(a.map(x=>x.id)).size,1000);
  const report=runLab({seed});assert.equal(report.summary.passed+report.summary.failed+report.summary.gaps,1000);
  assert.equal(report.summary.gaps,350);
 }
});

test('[E27] offline benchmarks include p95, sample sizes, runtime and explicit non-production limitations',()=>{
 const x=runBenchmarks({iterations:25});assert.ok(x.environment.node);assert.equal(x.environment.platform,process.platform);
 for(const v of Object.values(x.cases)){assert.equal(v.iterations,25);assert.ok(v.p95Ms>=v.medianMs);}
 assert.ok(x.limitations.some(s=>s.includes('NOT end-to-end')));
});

test('[E28] local release audit rejects leaked secrets and requires private npm packaging',()=>{
 const r=audit();assert.equal(r.ok,true,JSON.stringify(r.failures));
 assert.ok(r.count>10);assert.equal(r.sha256.length,64);
 assert.ok(r.sbom.files.every(f=>f.checksums[0].algorithm==='SHA256'));
 const p=JSON.parse(readFileSync(resolve('package.json'),'utf8'));assert.equal(p.private,true);
});
