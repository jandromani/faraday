import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {GraphStore} from '../lib/store.js';
import {isEligibleFreeModel, fetchFreeModels, explainFree, preparePrompt, makeGraphAdvisoryData} from '../lib/ai-free.js';

const free = {id:'openrouter/free',name:'Free Router',pricing:{prompt:'0',completion:'0'},architecture:{input_modalities:['text'],output_modalities:['text']}};
const specific = {...free,id:'google/gemma-4-31b-it:free'};
const paid = {...free,id:'openai/paid-model',pricing:{prompt:'0.000001',completion:'0.000001'}};
const fakeres = payload=>({ok:true,headers:{get:()=>null},text:async()=>JSON.stringify(payload)});

test('accept only explicitly free models with zero prices',()=>{
  assert.equal(isEligibleFreeModel(free),true);
  assert.equal(isEligibleFreeModel(specific),true);
  assert.equal(isEligibleFreeModel(paid),false);
  assert.equal(isEligibleFreeModel({...specific,pricing:{prompt:'0',completion:'0',request:'0.005'}}),false);
  assert.equal(isEligibleFreeModel({...specific,pricing:{prompt:'0',completion:'0',overrides:[{prompt:'0.1'}]}}),false);
  assert.equal(isEligibleFreeModel({...specific,id:'mystery-model'}),false);
  assert.equal(isEligibleFreeModel({...specific,architecture:{input_modalities:['image'],output_modalities:['image']}}),false);
});

test('catalog filter excludes paid models and non-text modalities',async()=>{
  const models=await fetchFreeModels({fetchImpl:async()=>fakeres({data:[free,paid,specific,{...specific,id:'audio/free:free',architecture:{input_modalities:['audio'],output_modalities:['audio']}}]})});
  assert.deepEqual(models.map(x=>x.id),['openrouter/free','google/gemma-4-31b-it:free']);
});

test('remote consent mandatory and cannot be bypassed with a key',async()=>{
  let count=0;
  await assert.rejects(explainFree({metadata:{a:1},apiKey:'fake',fetchImpl:async()=>{count++;return fakeres({data:[free]});}}),/--send-metadata/);
  assert.equal(count,0);
});

test('no API key blocks before network access',async()=>{
  let calls=0;
  await assert.rejects(explainFree({metadata:{a:1},consent:true,apiKey:'',fetchImpl:async()=>{calls++;return fakeres({data:[free]});}}),/OPENROUTER_API_KEY/);
  assert.equal(calls,0);
});

test('model paid or unverified -> no generation POST',async()=>{
  let calls=[];
  const impl=async(url,options)=>{calls.push([url,options.method]);return fakeres({data:[free,paid]});};
  await assert.rejects(explainFree({metadata:{a:1},consent:true,apiKey:'fake',model:'openai/paid-model',fetchImpl:impl}),/not verified free/);
  assert.deepEqual(calls.map(x=>x[1]),['GET']);
});

test('exact free-only request, no fallback or tools, no echoed secret',async()=>{
  const calls=[];
  const impl=async(url,options)=>{
    calls.push({url,options});
    return calls.length===1?fakeres({data:[free]}):fakeres({model:'openrouter/free',choices:[{message:{content:'Safe analysis'}}]});
  };
  const result=await explainFree({metadata:{nodes:[]},consent:true,apiKey:'super-secret',fetchImpl:impl});
  assert.equal(result.text,'Safe analysis');
  const body=JSON.parse(calls[1].options.body);
  assert.equal(body.model,'openrouter/free');
  assert.equal(body.tools,undefined);
  assert.equal(body.models,undefined);
  assert.equal(body.plugins,undefined);
  assert.equal(body.stream,false);
  assert.equal(calls[1].options.headers.Authorization,'Bearer super-secret');
  assert.equal(JSON.stringify(result).includes('super-secret'),false);
  assert.equal(calls[0].options.method,'GET');
  assert.equal(calls[1].options.method,'POST');
});

test('provider unavailable means no inference POST',async()=>{
  let count=0;
  await assert.rejects(explainFree({metadata:{a:1},consent:true,apiKey:'fake',fetchImpl:async()=>{count++;throw Error('offline');}}));
  assert.equal(count,1);
});

test('privacy: graph metadata excludes tool arguments, events and raw responses',()=>{
  const dir=mkdtempSync(join(tmpdir(),'faraday-ai-test-'));
  try {
    const store=new GraphStore(join(dir,'graph.sqlite'));
    store.inventory([{client:'demo',server:'mcp-demo',transport:'stdio'}]);
    store.event({server:'mcp-demo',direction:'request',kind:'tool_call',operation:'tools/call',tool:'compute'});
    const data=makeGraphAdvisoryData(store);
    assert.equal(data.nodes.length>0,true);
    assert.equal(data.edges.length>0,true);
    assert.equal(JSON.stringify(data).includes('operation'),false);
    assert.equal(JSON.stringify(data).includes('arguments'),false);
    assert.match(preparePrompt(data),/UNTRUSTED DATA/);
    store.close();
  } finally {rmSync(dir,{recursive:true,force:true});}
});

test('fail closed when outbound prompt exceeds limit',()=>{
  assert.throws(()=>preparePrompt({name:'x'.repeat(25000)}),/too large/);
});
