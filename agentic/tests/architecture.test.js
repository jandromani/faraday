import {test} from 'node:test';import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync,rmSync} from 'node:fs';import {fileURLToPath} from 'node:url';import {resolve,dirname,join} from 'node:path';import {tmpdir} from 'node:os';
import {fixture} from '../lib/authority-fixture.js';
import {newIdentity,digest} from '../lib/authority.js';
import * as Connect from '../packages/connect/index.js';
import * as Authority from '../packages/authority/index.js';
import * as Evidence from '../packages/evidence/index.js';
import * as Lab from '../packages/lab/index.js';
import * as PublicConnect from '@faraday/agentic/connect';
import * as PublicAuthority from '@faraday/agentic/authority-suite';
import * as PublicEvidence from '@faraday/agentic/evidence';
import * as PublicLab from '@faraday/agentic/lab-suite';
import * as PublicNative from '@faraday/agentic/native-pg-fencing';
import * as PublicLease from '@faraday/agentic/native-pg-lease';
import * as PublicDelegation from '@faraday/agentic/delegation-chain';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
test('Native PostgreSQL and signed delegation exports remain usable without a pg dependency at import time',()=>{
 assert.equal(typeof PublicNative.createNativePgFencedExecutor,'function');
 assert.equal(typeof PublicNative.createTlsVerifiedNativePgPool,'function');
 assert.equal(typeof PublicLease.createNativePgLeaseCoordinator,'function');
 assert.equal(typeof PublicDelegation.verifyDelegationChain,'function');
});
test('Four migration API surfaces bind to real existing implementations',()=>{
  assert.equal(typeof Connect.installProxy,'function');assert.equal(typeof Connect.probeStdio,'function');
  assert.equal(typeof Authority.AuthorityGate,'function');assert.equal(typeof Authority.PinnedOAuthResource,'function');assert.equal(typeof Authority.LocalOAuthRevocations,'function');assert.equal(typeof Authority.createStrictSecretFileProvider,'function');
  assert.equal(typeof Evidence.verifyReceipt,'function');assert.equal(typeof Evidence.evaluateAssurance,'function');assert.equal(typeof Evidence.verifyWitnessedEvidence,'function');
  assert.equal(typeof Lab.runLab,'function');assert.equal(Lab.DUMMY_AGENTS.length,12);
});
test('All packages are private, individually versioned, and exposed without breaking historical exports',()=>{
  const main=JSON.parse(readFileSync(resolve(root,'package.json'),'utf8'));
  assert.equal(main.private,true);assert.match(main.version,/^0\.99\.[0-9]+$/);
  for(const name of ['connect','authority','evidence','lab']){
    const pkg=JSON.parse(readFileSync(resolve(root,'packages',name,'package.json'),'utf8'));
    assert.equal(pkg.name,'@faraday/'+name);assert.equal(pkg.version,main.version);assert.equal(pkg.private,true);
  }
  for(const key of ['./connect','./authority-suite','./evidence','./lab-suite','./gateway','./mcp-oauth-resource'])assert.ok(main.exports[key]);
});
test('Architecture migration facades have no cross-package imports',()=>{
  for(const name of ['connect','authority','evidence','lab']){
    const s=readFileSync(resolve(root,'packages',name,'index.js'),'utf8');
    assert.doesNotMatch(s,/from ['"]\.\.\/[^.]/);assert.doesNotMatch(s,/process\.env/);
  }
});
test('Public preview APIs preserve synthetic cross-boundary contracts',()=>{
 assert.equal(PublicConnect.configServers,Connect.configServers);
 assert.equal(PublicAuthority.ToolPolicy,Authority.ToolPolicy);
 assert.equal(PublicEvidence.captureSynthetic,Evidence.captureSynthetic);
 assert.equal(PublicLab.generateScenarios,Lab.generateScenarios);
 for(const version of [PublicConnect.CONNECT_API_VERSION,PublicAuthority.AUTHORITY_API_VERSION,PublicEvidence.EVIDENCE_API_VERSION,PublicLab.LAB_API_VERSION])assert.equal(version,'1.0.0-preview');
 const server=PublicConnect.configServers({mcpServers:{sandbox:{command:'fixture'}}})[0];
 const scenario=PublicLab.generateScenarios(42).find(row=>row.category==='legitimate');
 const policy=new PublicAuthority.ToolPolicy({version:1,mode:'enforce',allowedTools:{[server.name]:['read_document']}},server.name);
 const request={jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'read_document',arguments:{id:'synthetic'}}};
 assert.equal(server.transport,'stdio');assert.equal(policy.decision(request).allowed,true);
 assert.equal(policy.decision({...request,params:{...request.params,name:'delete_everything'}}).allowed,false);
 const rule={agent:scenario.agent,tool:request.params.name,resource:'doc:fixture',op:'read'};
 const trace=PublicEvidence.captureSynthetic({policy:{allow:[rule]},intents:[{id:scenario.id,...rule,key:'synthetic'}]});
 assert.equal(trace.version,1);assert.equal(PublicEvidence.verifyTrace(trace).verified,true);
 assert.equal(PublicEvidence.replaySynthetic(trace,{policy:{allow:[]}}).divergences[0].now,'denied');
 assert.throws(()=>PublicEvidence.verifyTrace({...trace,version:2}),/Invalid synthetic trace envelope/);
 assert.throws(()=>PublicConnect.validateAdapterRecord({version:2,framework:'langgraph',agent:'id-'+'a'.repeat(24),tool:'id-'+'b'.repeat(24),kind:'tool_call',status:'ok',elapsed_ms:1}),/Unsupported adapter record value/);
});
test('Authority output is bound to an Evidence receipt through public APIs',t=>{
 const dir=mkdtempSync(join(tmpdir(),'faraday-boundary-'));
 const source=fixture(dir,{now:1700000000});t.after(()=>{source.close();rmSync(dir,{recursive:true,force:true});});
 assert.ok(source.gate instanceof PublicAuthority.AuthorityGate);
 const auth=source.gate.authorize({capability:source.capability,proof:source.proof});
 const signer=newIdentity();
 const claims={version:1,operationId:auth.jti,agent:auth.agent,tool:auth.tool,resource:auth.resource,action:auth.action,
  argsHash:digest(auth.args),requestHash:digest({tool:auth.tool,resource:auth.resource,action:auth.action,args:auth.args}),
  rule:auth.rule,outcome:'upstream-uncertain',responseHash:null,backendAttestation:null,observedAt:1700000000};
 const receipt=PublicEvidence.signReceipt({privatePem:signer.privatePem,claims});
 const verified=PublicEvidence.verifyReceipt({publicPem:signer.publicPem,receipt});
 assert.equal(verified.operationId,auth.jti);assert.equal(verified.outcome,'upstream-uncertain');assert.equal(verified.backendVerified,false);
 assert.throws(()=>PublicEvidence.verifyReceipt({publicPem:signer.publicPem,receipt:{...receipt,claims:{...claims,resource:'invoice:other'}}}),/invalid-receipt-signature/);
 assert.throws(()=>source.gate.authorize({capability:source.capability,proof:source.proof}),/replayed/);
});
test('Threat model references existing local evidence',()=>{
 const model=readFileSync(resolve(root,'docs/THREAT_MODEL.md'),'utf8');
 for(const category of ['Spoofing','Tampering','Repudiation','Information disclosure','Denial of service','Elevation of privilege'])assert.ok(model.includes(category),category);
 for(const topology of ['T1:','T2:','T3:'])assert.ok(model.includes(topology),topology);
 const rows=model.split('\n').filter(line=>/^\| TM-\d\d \|/.test(line));
 assert.equal(rows.length,13);assert.equal(new Set(rows.map(row=>row.split('|')[1].trim())).size,13);
 for(const row of rows){
  const cells=row.split('|').slice(1,-1).map(cell=>cell.trim());assert.equal(cells.length,5);
  assert.match(cells[1],/P[01] \/ T[123]/);assert.ok(cells[2]);assert.match(cells[3],/\]\(\.\.\/tests\//);
    assert.match(cells[4],/owners?:/i);
 }
 const references=[...model.matchAll(/\]\((\.\.\/tests\/[^)]+)\)/g)];assert.ok(references.length>=13);
 for(const match of references)assert.ok(readFileSync(resolve(root,'docs',match[1]),'utf8').includes('test('),match[1]);
});
