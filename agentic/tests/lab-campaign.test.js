import test from 'node:test';
import assert from 'node:assert/strict';
import {runAdaptiveLabCampaign,runMultiAgentLab} from '../lib/lab-campaign.js';

test('E24 adaptive local campaign checks denials, positive control and replay effects',async()=>{
 const report=await runAdaptiveLabCampaign();
 assert.equal(report.result,'pass');assert.equal(report.backendOperations,1);
 assert.deepEqual(report.steps.map(step=>[step.name,step.status,step.effects]),[
  ['alter-arguments','blocked',0],['omit-proof','blocked',0],['omit-approvals','blocked',0],['direct-without-secret','blocked',0],['positive-control','executed',1],['replay','blocked',0]]);
 assert.equal(report.steps.find(step=>step.name==='positive-control').receiptVerified,true);
});
test('E24 adaptive campaign stops and reports a bypass instead of a pass',async()=>{
 let effects=0,closed=false;
 const fake={issue:()=>({}),store:{count:()=>effects},call:async()=>{effects++;return {status:200};},close:async()=>{closed=true;}};
 const report=await runAdaptiveLabCampaign({createHarness:async()=>fake});
 assert.equal(report.result,'fail');assert.equal(report.steps.length,1);assert.equal(report.steps[0].status,'bypass');assert.equal(closed,true);
});
test('E23 scripted actors delegate via reviewed memory and invoke the synthetic gateway',async()=>{
 const first=await runMultiAgentLab({seed:17}),second=await runMultiAgentLab({seed:17});
 assert.deepEqual(first,second);assert.equal(first.result,'simulated');assert.equal(first.backendOperations,1);
 assert.equal(first.steps.at(-1).receiptVerified,true);
 assert.deepEqual(first.steps.filter(step=>step.action==='delegate').map(step=>step.to),['reviewer','finance']);
});
test('E23 reproducible local faults stop effects or leave an uncertain backend outcome',async()=>{
 for(const [fault,result] of [['quarantined-memory','blocked'],['expired-memory','blocked'],['altered-arguments','blocked'],['backend-unavailable','uncertain']]){
  const report=await runMultiAgentLab({seed:17,fault});assert.equal(report.result,result,fault);assert.equal(report.backendOperations,0,fault);
 }
 await assert.rejects(runMultiAgentLab({seed:-1}),/invalid-multiagent-scenario/);
 await assert.rejects(runMultiAgentLab({fault:'unknown'}),/invalid-multiagent-scenario/);
});
test('E24 an unexpected effect is a failure even on HTTP denial',async()=>{
 let effects=0;
 const fake={issue:()=>({}),store:{count:()=>effects},call:async()=>{effects++;return {status:403};},close:async()=>{}};
 const report=await runAdaptiveLabCampaign({createHarness:async()=>fake});
 assert.equal(report.result,'fail');assert.equal(report.steps[0].status,'bypass');
});
test('E23 discarded response and replay do not duplicate the synthetic effect',async()=>{
 const report=await runMultiAgentLab({seed:17,fault:'lost-response'});
 assert.equal(report.result,'simulated');assert.equal(report.backendOperations,1);
 assert.deepEqual(report.steps.at(-1),{actor:'finance',action:'retry',http:403,effects:0});
});