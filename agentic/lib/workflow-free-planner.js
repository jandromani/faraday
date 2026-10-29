/** Optional OpenRouter free-model text planner for the synthetic workflow ONLY.
 * The LLM has no signing key, no direct access to the backend, and cannot authorize actions.
 * No inference takes place unless the caller explicitly opts into external processing.
 */
import {fetchFreeModels} from './ai-free.js';
const BASE='https://openrouter.ai/api/v1';
export const DEFAULT_FREE_MODEL='openrouter/free';
export const SYNTHETIC_TASK={tool:'pay_invoice',arguments:{amount_cents:9500,currency:'EUR',recipient:'supplier_demo'}};
export const FIXED_SYNTHETIC_PROMPT='For a SYNTHETIC training-only invoice, choose the single tool invocation. Reply with raw JSON only (no code fences): {"tool":"pay_invoice","arguments":{"amount_cents":9500,"currency":"EUR","recipient":"supplier_demo"}}. You may instead return {"tool":"none"}. This is an untrusted recommendation; FARADAY enforces the permitted scope. No real transfer will occur.';
async function boundedJson(response){
  if(!response?.ok)throw Error('Free model unavailable or rate-limited');
  const len=Number(response.headers?.get?.('content-length')||0);if(len>32_768)throw Error('Oversized model response');
  const reader=response.body?.getReader();if(!reader)throw Error('Missing model response body');
  let size=0;const pieces=[];
  try{while(true){const {value,done}=await reader.read();if(done)break;size+=value.length;if(size>32_768)throw Error('Oversized model response');pieces.push(value);}}
  finally{reader.releaseLock();}
  return JSON.parse(Buffer.concat(pieces).toString('utf8'));
}
export function parseSyntheticPlan(text){
  if(typeof text!=='string'||text.length>600||text.length===0)throw Error('Invalid model plan');
  let plan;try{plan=JSON.parse(text);}catch{throw Error('Non-JSON model plan rejected');}
  if(!plan||typeof plan!=='object'||Array.isArray(plan)||Object.keys(plan).sort().join('|')!=='arguments|tool'&&Object.keys(plan).join('|')!=='tool')throw Error('Unexpected model plan fields');
  if(plan.tool==='none'&&Object.keys(plan).length===1)return {authorized:false,reason:'model-declined'};
  if(plan.tool!=='pay_invoice'||!plan.arguments||typeof plan.arguments!=='object'||Array.isArray(plan.arguments)||
     Object.keys(plan.arguments).sort().join('|')!=='amount_cents|currency|recipient'||
     plan.arguments.amount_cents!==9500||plan.arguments.currency!=='EUR'||plan.arguments.recipient!=='supplier_demo')
    return {authorized:false,reason:'scope-mismatch'};
  return {authorized:true,tool:'pay_invoice',arguments:{...SYNTHETIC_TASK.arguments}};
}
export async function generateFreeSyntheticPlan({consent=false,apiKey=process.env.OPENROUTER_API_KEY,
    model=DEFAULT_FREE_MODEL,fetchImpl=fetch}={}){
  if(!consent)throw Error('Free model requires explicit --send-intent; no request sent');
  if(typeof apiKey!=='string'||!apiKey)throw Error('OPENROUTER_API_KEY missing; no request sent');
  const free=await fetchFreeModels({fetchImpl});
  if(!free.some(x=>x.id===model))throw Error('Model not verified as zero-priced; no generation sent');
  const response=await fetchImpl(`${BASE}/chat/completions`,{method:'POST',redirect:'error',signal:AbortSignal.timeout(35_000),
    headers:{'authorization':`Bearer ${apiKey}`,'content-type':'application/json','accept':'application/json'},
    body:JSON.stringify({model,max_tokens:200,stream:false,messages:[{role:'user',content:FIXED_SYNTHETIC_PROMPT}]})});
  const body=await boundedJson(response);
  if(body.usage?.cost!=null&&(!Number.isFinite(Number(body.usage.cost))||Number(body.usage.cost)!==0))throw Error('Provider reported nonzero inference cost');
  const text=body.choices?.[0]?.message?.content;
  if(typeof text!=='string')throw Error('Free model provided no parsable text');
  return {text,model:String(body.model||model).slice(0,160),reportedCost:body.usage?.cost??null};
}
