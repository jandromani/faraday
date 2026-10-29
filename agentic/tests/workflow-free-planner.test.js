import test from 'node:test';
import assert from 'node:assert/strict';
import {generateFreeSyntheticPlan,SYNTHETIC_TASK} from '../lib/workflow-free-planner.js';

const reply=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json'}});
const catalog={data:[{id:'google/gemma-4-31b-it:free',pricing:{prompt:'0',completion:'0'},architecture:{input_modalities:['text'],output_modalities:['text']}},
  {id:'fake/premium:free',pricing:{prompt:'0.1',completion:'0.1'}}]};
const good=JSON.stringify(SYNTHETIC_TASK);
test('free-only route checks catalog before generation and never leaks secrets into prompt',async()=>{
  const calls=[];const fetchImpl=async(url,options)=>{calls.push({url,options});return url.endsWith('/models')?reply(catalog):reply({choices:[{message:{content:good}}],usage:{cost:0},model:'google/gemma-4-31b-it:free'});};
  const x=await generateFreeSyntheticPlan({consent:true,apiKey:'synthetic_secret',model:'google/gemma-4-31b-it:free',fetchImpl});
  assert.equal(x.text,good);assert.equal(x.reportedCost,0);assert.equal(calls.length,2);
  assert.ok(!calls[1].options.body.includes('synthetic_secret'));
  assert.ok(!calls[1].options.body.includes('PRIVATE KEY'));
});
test('without consent or key no fetch happens',async()=>{
  let calls=0;const fetchImpl=async()=>{calls++;throw Error('must not fetch');};
  await assert.rejects(()=>generateFreeSyntheticPlan({consent:false,apiKey:'x',fetchImpl}),/send-intent/);
  await assert.rejects(()=>generateFreeSyntheticPlan({consent:true,apiKey:'',fetchImpl}),/missing/);
  assert.equal(calls,0);
});
test('paid and unknown models rejected before generation',async()=>{
  let posts=0;const fetchImpl=async(url)=>{if(url.endsWith('/models'))return reply(catalog);posts++;return reply({choices:[]});};
  await assert.rejects(()=>generateFreeSyntheticPlan({consent:true,apiKey:'fake',model:'fake/premium:free',fetchImpl}),/zero-priced/);
  await assert.rejects(()=>generateFreeSyntheticPlan({consent:true,apiKey:'fake',model:'unknown/free',fetchImpl}),/zero-priced/);
  assert.equal(posts,0);
});
test('positive reported cost rejects response; no paid fallback',async()=>{
  const fetchImpl=async url=>url.endsWith('/models')?reply(catalog):reply({choices:[{message:{content:good}}],usage:{cost:0.01}});
  await assert.rejects(()=>generateFreeSyntheticPlan({consent:true,apiKey:'fake',model:'google/gemma-4-31b-it:free',fetchImpl}),/nonzero/);
});
