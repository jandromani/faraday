import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtempSync,rmSync,writeFileSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {DUMMY_AGENTS,DISTRIBUTION,generateScenarios,runLab} from '../lib/lab.js';
import {diffAuthority,affectedClients,simulateObservedDecisions} from '../lib/trust-diff.js';
import {compatibilityReport} from '../lib/compatibility.js';
import {GraphStore} from '../lib/store.js';
import {safeLabel} from '../lib/discover.js';

const CLI=resolve('bin/faraday.js');
const before={version:1,mode:'enforce',maxArgumentBytes:8192,allowedTools:{sandbox:['read_document']}};
const after={version:1,mode:'enforce',maxArgumentBytes:16384,allowedTools:{sandbox:['read_document','delete_everything']}};
function dir(t){const path=mkdtempSync(join(tmpdir(),'faraday-lab-v08-'));t.after(()=>rmSync(path,{recursive:true,force:true}));return path;}
const cli=(args)=>spawnSync(process.execPath,[CLI,...args],{encoding:'utf8',timeout:15000});

test('12 distinct dummy actors are synthetic, not externally connected',()=>{
 assert.equal(DUMMY_AGENTS.length,12);
 assert.equal(new Set(DUMMY_AGENTS.map(x=>x.id)).size,12);
 assert.ok(DUMMY_AGENTS.every(x=>x.kind==='synthetic'&&!x.canReachProduction));
});
test('1,000 unique scenarios have exact category distribution',()=>{
 const rows=generateScenarios(42);assert.equal(rows.length,1000);
 assert.equal(new Set(rows.map(x=>x.id)).size,1000);
 for(const [type,count] of Object.entries(DISTRIBUTION))assert.equal(rows.filter(x=>x.category===type).length,count);
});
test('scenario corpus repeatable for fixed seed',()=>assert.deepEqual(generateScenarios(123),generateScenarios(123)));
test('scenario corpus exercises all actors and local rule variants',()=>{
 for(const seed of [0,42,123]){
  const rows=generateScenarios(seed);
  assert.equal(new Set(rows.map(row=>row.agent)).size,DUMMY_AGENTS.length);
  assert.equal(new Set(rows.filter(row=>row.category==='legitimate').map(row=>row.variant%2)).size,2);
  assert.equal(new Set(rows.filter(row=>row.category==='ssrf').map(row=>row.variant%4)).size,4);
 }
});
test('changing seed changes synthetic variants',()=>assert.notDeepEqual(generateScenarios(123),generateScenarios(124)));
test('lab reports verified checks vs unsupported controls separately',()=>{
 const report=runLab();
 assert.deepEqual(report.summary,{total:1000,passed:650,failed:0,gaps:350});
 assert.equal(report.categories.authorization.passed,200);
 assert.equal(report.categories.ssrf.passed,100);
 assert.equal(report.categories.contracts.passed,100);
 assert.equal(report.categories.prompt_injection.gaps,150);
 assert.equal(report.categories.identity.gaps,100);
 assert.equal(report.categories.chaos.gaps,100);
});
test('repeatable report evidence fingerprint',()=>{
 assert.equal(runLab({seed:12}).sha256,runLab({seed:12}).sha256);
 assert.notEqual(runLab({seed:12}).sha256,runLab({seed:13}).sha256);
 const report=runLab({seed:12,includeCases:true});
 const evidence={seed:report.seed,results:report.cases,categories:report.categories,summary:report.summary};
 assert.equal(report.sha256,createHash('sha256').update(JSON.stringify(evidence)).digest('hex'));
});
test('unbounded lab execution rejected',()=>{
 for(const bad of [0,-1,1001,1.25,NaN,Infinity])assert.throws(()=>runLab({limit:bad}));
});
test('invalid seeds rejected',()=>{
 for(const seed of [-1,2**32,1.25,NaN])assert.throws(()=>generateScenarios(seed));
});
test('full report case details are opt-in',()=>{
 assert.equal(runLab({limit:10}).cases,undefined);
 assert.equal(runLab({limit:10,includeCases:true}).cases.length,10);
});
test('TrustDiff detects allowlist and argument-limit expansion',()=>{
 const r=diffAuthority(before,after);
 assert.deepEqual(r.added,[{server:'sandbox',tool:'delete_everything'}]);
 assert.equal(r.summary.authorityExpanded,true);
 assert.equal(r.maxArgumentBytes.expanded,true);
});
test('E20 observed-decision preflight uses ToolPolicy without exposing request contents',()=>{
 const previous={version:1,mode:'enforce',allowedTools:{sandbox:['read_document']},maxArgumentBytes:32};
 const proposed={...previous,allowedTools:{sandbox:['read_document','secret-tool-name']},maxArgumentBytes:100};
 const message={jsonrpc:'2.0',method:'tools/call',params:{name:'secret-tool-name',arguments:{value:'sensitive-value'}}};
 const report=simulateObservedDecisions(previous,proposed,[{server:'sandbox',message,observedAllowed:false},{server:'sandbox',message,observedAllowed:true}]);
 assert.deepEqual(report.results.map(result=>[result.baseline,result.proposed,result.baselineMatches]),[['deny','allow',true],['deny','allow',false]]);
 assert.equal(report.summary.baselineMismatches,1);assert.equal(report.summary.changed,2);
 assert.equal(JSON.stringify(report).includes('secret-tool-name'),false);assert.equal(JSON.stringify(report).includes('sensitive-value'),false);
 assert.throws(()=>simulateObservedDecisions(previous,proposed,[{server:'sandbox',message}]),/Invalid observed decision/);
 assert.equal(simulateObservedDecisions(previous,{...proposed,allowedTools:{}},[{server:'sandbox',message,observedAllowed:false}]).results[0].proposed,'configuration-error');
});
test('E20 trust CLI compares explicit local observations without executing a tool',t=>{
 const path=dir(t),base=join(path,'before.json'),current=join(path,'after.json'),observations=join(path,'observations.json');
 writeFileSync(base,JSON.stringify(before));writeFileSync(current,JSON.stringify(after));
 writeFileSync(observations,JSON.stringify([{server:'sandbox',message:{jsonrpc:'2.0',method:'tools/call',params:{name:'delete_everything',arguments:{secret:'private-value'}}},observedAllowed:false}]));
 const result=cli(['trust','diff','--base',base,'--current',current,'--observations',observations]);assert.equal(result.status,0,result.stderr);
 const report=JSON.parse(result.stdout);assert.equal(report.observedDecisionSimulation.results[0].proposed,'allow');
 assert.equal(report.observedDecisionSimulation.summary.baselineMismatches,0);assert.equal(result.stdout.includes('private-value'),false);
 writeFileSync(observations,JSON.stringify([{server:'sandbox',message:{jsonrpc:'2.0',method:'tools/call',params:{name:'delete_everything',arguments:{}}},observedAllowed:true}]));
 assert.equal(cli(['trust','diff','--base',base,'--current',current,'--observations',observations,'--fail-on-divergence']).status,2);
 assert.notEqual(cli(['trust','diff','--base',base,'--current',current,'--fail-on-divergence']).status,0);
});
test('TrustDiff detects contraction without false expansion',()=>{
 const r=diffAuthority(after,before);
 assert.deepEqual(r.removed,[{server:'sandbox',tool:'delete_everything'}]);
 assert.equal(r.summary.authorityExpanded,false);
});
test('TrustDiff detects method expansion and removing method restrictions',()=>{
 const strict={...before,allowedMethods:['initialize','tools/call']};
 const expanded={...strict,allowedMethods:['initialize','tools/call','resources/read']};
 assert.equal(diffAuthority(before,strict).summary.authorityExpanded,false);
 assert.equal(diffAuthority(strict,before).summary.authorityExpanded,true);
 assert.equal(diffAuthority(strict,before).methods.unrestrictedMethods,true);
 assert.deepEqual(diffAuthority(strict,expanded).methods.added,['resources/read']);
 assert.equal(diffAuthority(strict,expanded).summary.authorityExpanded,true);
 assert.equal(diffAuthority(expanded,strict).summary.authorityExpanded,false);
 assert.throws(()=>diffAuthority(strict,{...strict,allowedMethods:null}),/method allowlist/);
 assert.throws(()=>diffAuthority(strict,{...strict,unknown:'new-authority'}),/Invalid FARADAY policy/);
});
test('TrustDiff detects expansion even when redacted labels collide',()=>{
 const sensitive='secret-tool-name',alias=safeLabel(sensitive);
 const base={...before,allowedTools:{sandbox:[sensitive]}};
 const current={...before,allowedTools:{sandbox:[alias]}};
 const result=diffAuthority(base,current);
 assert.equal(result.summary.authorityExpanded,true);
 assert.equal(result.summary.added,1);assert.equal(result.summary.removed,1);
 assert.ok(!JSON.stringify(result).includes(sensitive));
});
test('TrustDiff rejects malformed policies and deduplicates entries',()=>{
 assert.throws(()=>diffAuthority({},after));
 const x={...before,allowedTools:{sandbox:['read_document','read_document']}};
 assert.equal(diffAuthority(x,before).summary.added,0);
});
test('potential impact is drawn from configured graph edges',t=>{
 const path=dir(t);const store=new GraphStore(join(path,'graph.sqlite'));
 store.inventory([{client:'synthetic-ide',server:'sandbox',transport:'stdio',source:'workspace:.mcp.json'}]);
 assert.deepEqual(affectedClients(store.snapshot(),'sandbox'),['synthetic-ide']);
 store.close();
});
test('CLI shows 12 agents and truthful evaluation summary',()=>{
 const a=cli(['lab','agents']);assert.equal(a.status,0);
 assert.equal(JSON.parse(a.stdout).agents.length,12);
 const r=cli(['lab','run']);assert.equal(r.status,0);
 assert.equal(JSON.parse(r.stdout).summary.gaps,350);
});
test('release --fail-on-gap exit status is 2, not false success',()=>{
 assert.equal(cli(['lab','run','--fail-on-gap']).status,2);
});
test('report export is non-destructive and contains 1,000 cases',t=>{
 const path=dir(t),file=join(path,'eval.json');
 assert.equal(cli(['lab','run','--out',file]).status,0);
 assert.equal(JSON.parse(readFileSync(file,'utf8')).cases.length,1000);
 assert.equal(cli(['lab','run','--out',file]).status,1);
});
test('CLI flags privilege expansion as exit code 2',t=>{
 const path=dir(t),a=join(path,'a.json'),b=join(path,'b.json');
 writeFileSync(a,JSON.stringify(before));writeFileSync(b,JSON.stringify(after));
 const r=cli(['trust','diff','--base',a,'--current',b,'--fail-on-expansion']);
 assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).summary.authorityExpanded,true);
});
test('CLI accepts restrictions without false alerts',t=>{
 const path=dir(t),a=join(path,'a.json'),b=join(path,'b.json');
 writeFileSync(a,JSON.stringify(after));writeFileSync(b,JSON.stringify(before));
 assert.equal(cli(['trust','diff','--base',a,'--current',b,'--fail-on-expansion']).status,0);
});
test('static compatibility report never claims live certification',t=>{
 const path=dir(t);
 writeFileSync(join(path,'.mcp.json'),JSON.stringify({mcpServers:{fixture:{command:'node',args:['fixture.js']}}}));
 const r=compatibilityReport({root:path});
 assert.equal(r.summary.configured,1);assert.equal(r.summary.verifiedLive,0);
 assert.equal(r.servers[0].conformance,'untested');
});
test('legacy SSE is inventoried, not marked supported',t=>{
 const path=dir(t);
 writeFileSync(join(path,'.mcp.json'),JSON.stringify({mcpServers:{legacy:{type:'sse',url:'https://example.invalid'}}}));
 const r=compatibilityReport({root:path});assert.equal(r.servers[0].eligibleForBridge,false);
});
test('unknown explicit transports are not assumed bridge-compatible',t=>{
 const path=dir(t);
 writeFileSync(join(path,'.mcp.json'),JSON.stringify({mcpServers:{unknown:{type:'websocket',url:'https://example.invalid'}}}));
 const r=compatibilityReport({root:path});
 assert.equal(r.servers[0].transport,'unknown');assert.equal(r.servers[0].eligibleForBridge,false);
 assert.match(r.servers[0].warning,/Unrecognized transport/);
});
test('compat report never prints credentials',t=>{
 const path=dir(t),secret='FAKE_DEV_TOKEN_DO_NOT_LOG';
 writeFileSync(join(path,'.mcp.json'),JSON.stringify({mcpServers:{remote:{type:'http',url:'https://example.invalid/mcp',headers:{Authorization:secret}}}}));
 const r=cli(['compat','--root',path]);assert.equal(r.status,0);
 assert.equal(r.stdout.includes(secret),false);
});
test('fixture presents 12 MCP tools through a real stdio process',async t=>{
 const path=dir(t),folder=join(path,'fixture');
 assert.equal(cli(['lab','fixture','--out',folder]).status,0);
 const config=JSON.parse(readFileSync(join(folder,'mcp.json'),'utf8'));
 const script=config.mcpServers['faraday-synthetic-lab'].args[0];
 const proc=spawn(process.execPath,[script],{stdio:['pipe','pipe','pipe']});
 t.after(()=>proc.kill());
 let output='';
 const promise=new Promise((done,reject)=>{
  const timer=setTimeout(()=>{proc.kill();reject(Error('fixture timeout'));},4000);
  proc.stdout.on('data',data=>{output+=data;if(output.includes('\n')){clearTimeout(timer);done(JSON.parse(output.split('\n')[0]));}});
  proc.once('error',reject);
 });
 proc.stdin.write(JSON.stringify({jsonrpc:'2.0',id:7,method:'tools/list',params:{}})+'\n');
 const msg=await promise;assert.equal(msg.result.tools.length,12);
 proc.stdin.end();
});
test('fixture creation never overwrites existing local configuration',t=>{
 const path=dir(t),folder=join(path,'fixture');
 assert.equal(cli(['lab','fixture','--out',folder]).status,0);
 assert.equal(cli(['lab','fixture','--out',folder]).status,1);
});
