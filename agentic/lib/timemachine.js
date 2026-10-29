/** FARADAY TimeMachine v0.97 — replay ONLY of synthetic, explicitly typed, offline intents.
 * NEVER connects to an MCP server, executes a tool, or reproduces a real side effect.
 * SHA-256 chain catches accidental/unauthorized changes without proving origin/authenticity.
 */
import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {lstatSync,readFileSync} from 'node:fs';
import {DUMMY_AGENTS} from './lab.js';
import {canonical} from './authority.js';

const FORMAT='faraday-synthetic-timemachine';
const CHECKPOINT_FORMAT='faraday-synthetic-trace-checkpoint-v1';
const CHECKPOINT_DOMAIN=Buffer.from('FARADAY-SYNTHETIC-TRACE-CHECKPOINT-V1\0');
const validName=x=>typeof x==='string'&&x.length>0&&x.length<=96&&/^[a-zA-Z0-9_.:-]+$/.test(x);
const validOp=new Set(['read','write']);
const sha=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const isObj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
function assertKeys(x,keys){if(!isObj(x)||Object.keys(x).some(k=>!keys.includes(k)))throw Error('Invalid TimeMachine object');}
export function validatePolicy(policy){
  assertKeys(policy,['allow']);if(!Array.isArray(policy.allow)||policy.allow.length>256)throw Error('Invalid replay policy');
  const seen=new Set();
  for(const rule of policy.allow){
    assertKeys(rule,['agent','tool','resource','op']);
    if(![rule.agent,rule.tool,rule.resource].every(validName)||!validOp.has(rule.op))throw Error('Invalid replay rule');
    const id=sha(rule);if(seen.has(id))throw Error('Duplicate replay rule');seen.add(id);
  }
  return policy;
}
function validateIntent(intent){
  assertKeys(intent,['id','agent','tool','resource','op','key','value']);
  if(![intent.id,intent.agent,intent.tool,intent.resource,intent.key].every(validName)||!validOp.has(intent.op))throw Error('Invalid synthetic intent');
  if(intent.op==='write'&&(!Number.isSafeInteger(intent.value)||intent.value<0||intent.value>100000))throw Error('Invalid synthetic value');
  if(intent.op==='read'&&intent.value!==undefined)throw Error('Read intent cannot set value');
  return intent;
}
function compute(policy,intents){
  validatePolicy(policy);
  if(!Array.isArray(intents)||intents.length>256)throw Error('Too many synthetic intents');
  const authorized=new Set(policy.allow.map(r=>[r.agent,r.tool,r.resource,r.op].join('\0')));
  const seen=new Map(),state=new Map(),steps=[];
  for(const [seq,original] of intents.entries()){
    const intent=validateIntent(original);
    const key=[intent.agent,intent.tool,intent.resource,intent.op].join('\0');
    let outcome='denied';
    if(authorized.has(key)){
      const prior=seen.get(intent.id),bodyHash=sha(intent);
      if(prior)outcome=prior===bodyHash?'duplicate':'idempotency-conflict';
      else{
        seen.set(intent.id,bodyHash);
        if(intent.op==='write'){state.set(intent.key,intent.value);outcome='applied';}
        else outcome='read';
      }
    }
    const stateHash=sha([...state.entries()].sort((a,b)=>a[0].localeCompare(b[0])));
    steps.push({seq,intent:{...intent},outcome,stateHash});
  }
  return {steps,finalStateHash:sha([...state.entries()].sort((a,b)=>a[0].localeCompare(b[0]))),sideEffects:'in-memory-synthetic-only'};
}
export function syntheticFixture(seed=42){
  if(!Number.isSafeInteger(seed)||seed<0||seed>0xffffffff)throw Error('Invalid synthetic seed');
  const agents=DUMMY_AGENTS.map(a=>a.id);
  const policy={allow:[
    {agent:'explorer',tool:'read_document',resource:'doc:demo',op:'read'},
    {agent:'finance',tool:'pay_invoice',resource:'invoice:demo',op:'write'},
    {agent:'support',tool:'read_ticket',resource:'ticket:demo',op:'read'},
    {agent:'deployer',tool:'deploy_fixture',resource:'release:demo',op:'write'}
  ]};
  // The seed only changes safe in-memory values. No model or external API is invoked.
  const value=(seed%500)+1;
  const intents=agents.map((agent,i)=>({id:`fixture-${i+1}`,agent,
    tool:i%3===0?'read_document':i%3===1?'pay_invoice':'read_ticket',
    resource:i%3===0?'doc:demo':i%3===1?'invoice:demo':'ticket:demo',
    op:i%3===1?'write':'read',key:`synthetic:${i}`, ...(i%3===1?{value:value+i}:{})}));
  intents.push({id:'fixture-20',agent:'finance',tool:'pay_invoice',resource:'invoice:demo',op:'write',key:'synthetic:invoice',value});
  intents.push({...intents.at(-1)}); // idempotent duplicate
  intents.push({id:'fixture-21',agent:'adversary',tool:'pay_invoice',resource:'invoice:demo',op:'write',key:'synthetic:invoice',value:9999});
  return {policy,intents};
}
export function captureSynthetic({seed=42,policy,intents}={}){
  if(!Number.isSafeInteger(seed)||seed<0||seed>0xffffffff)throw Error('Invalid synthetic seed');
  if((policy===undefined)!==(intents===undefined))throw Error('Synthetic policy and intents must be provided together');
  const fixture=policy===undefined?syntheticFixture(seed):{policy,intents};
  const computed=compute(fixture.policy,fixture.intents),steps=[];
  let prevHash='0'.repeat(64);
  for(const entry of computed.steps){
    const record={...entry,prevHash};const hash=sha(record);steps.push({...record,hash});prevHash=hash;
  }
  return {format:FORMAT,version:1,kind:'offline-synthetic',seed,policy:fixture.policy,steps,rootHash:prevHash,
    metadataHash:sha({format:FORMAT,version:1,kind:'offline-synthetic',seed,policy:fixture.policy,limitations:[
      'Hash chain provides alteration detection, not signed provenance or immutable storage.',
      'Only synthetic intents and in-memory state. No real MCP tool execution, prompts, network or filesystem side effects.']}),
    limitations:['Hash chain provides alteration detection, not signed provenance or immutable storage.',
      'Only synthetic intents and in-memory state. No real MCP tool execution, prompts, network or filesystem side effects.']};
}
export function verifyTrace(trace){
  assertKeys(trace,['format','version','kind','seed','policy','steps','rootHash','metadataHash','limitations']);
  if(!isObj(trace)||trace.format!==FORMAT||trace.version!==1||trace.kind!=='offline-synthetic'||
     !Number.isSafeInteger(trace.seed)||trace.seed<0||!Array.isArray(trace.steps)||trace.steps.length>256||
     !Array.isArray(trace.limitations)||trace.limitations.length>12)throw Error('Invalid synthetic trace envelope');
  validatePolicy(trace.policy);
  if(trace.metadataHash!==sha({format:trace.format,version:trace.version,kind:trace.kind,seed:trace.seed,policy:trace.policy,limitations:trace.limitations}))throw Error('TimeMachine metadata corruption');
  let previous='0'.repeat(64);
  for(const [i,step] of trace.steps.entries()){
    assertKeys(step,['seq','intent','outcome','stateHash','prevHash','hash']);
    if(step.seq!==i||step.prevHash!==previous||typeof step.stateHash!=='string'||! /^[a-f0-9]{64}$/.test(step.stateHash))throw Error('TimeMachine chain corruption');
    validateIntent(step.intent);
    const calculated=sha({seq:i,intent:step.intent,outcome:step.outcome,stateHash:step.stateHash,prevHash:previous});
    if(step.hash!==calculated)throw Error('TimeMachine chain corruption');
    previous=step.hash;
  }
  if(trace.rootHash!==previous)throw Error('TimeMachine root mismatch');
  // A modified trace with recomputed hashes must still be consistent with its own policy and simulation.
  const original=compute(trace.policy,trace.steps.map(s=>s.intent));
  for(const [i,s] of trace.steps.entries())if(s.outcome!==original.steps[i].outcome||s.stateHash!==original.steps[i].stateHash)
    throw Error('TimeMachine recorded outcome inconsistent with policy');
  return {verified:true,steps:trace.steps.length,rootHash:trace.rootHash,kind:trace.kind,authenticity:'not-proven'};
}
export function signSyntheticCheckpoint({trace,privatePem,witnessId,issuedAt=Date.now()}={}){
 const integrity=verifyTrace(trace);
 if(!validName(witnessId)||!Number.isSafeInteger(issuedAt)||issuedAt<1)throw Error('Invalid synthetic checkpoint');
 const key=createPrivateKey(privatePem);if(key.asymmetricKeyType!=='ed25519')throw Error('Invalid synthetic checkpoint key');
 const claims={format:CHECKPOINT_FORMAT,traceDigest:sha(trace),rootHash:integrity.rootHash,steps:integrity.steps,witnessId,issuedAt};
 return {claims,signature:sign(null,Buffer.concat([CHECKPOINT_DOMAIN,canonical(claims)]),key).toString('base64url')};
}
export function verifySyntheticCheckpoint({trace,checkpoint,publicPem,expectedWitnessId,expectedDigest}={}){
 const integrity=verifyTrace(trace);
 if(!isObj(checkpoint)||Object.keys(checkpoint).length!==2||!Object.hasOwn(checkpoint,'claims')||!Object.hasOwn(checkpoint,'signature'))throw Error('Invalid synthetic checkpoint');
 const {claims,signature}=checkpoint,keys=['format','traceDigest','rootHash','steps','witnessId','issuedAt'];
 if(!isObj(claims)||Object.keys(claims).length!==keys.length||!keys.every(key=>Object.hasOwn(claims,key))||claims.format!==CHECKPOINT_FORMAT||
   !validName(expectedWitnessId)||claims.witnessId!==expectedWitnessId||!Number.isSafeInteger(claims.issuedAt)||claims.issuedAt<1||
   typeof signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signature)||Buffer.from(signature,'base64url').toString('base64url')!==signature)throw Error('Invalid synthetic checkpoint');
 const key=createPublicKey(publicPem);if(key.asymmetricKeyType!=='ed25519'||!verify(null,Buffer.concat([CHECKPOINT_DOMAIN,canonical(claims)]),key,Buffer.from(signature,'base64url')))throw Error('Invalid synthetic checkpoint signature');
 if(claims.traceDigest!==sha(trace)||claims.rootHash!==integrity.rootHash||claims.steps!==integrity.steps)throw Error('Synthetic checkpoint trace mismatch');
 const checkpointDigest=createHash('sha256').update(canonical(checkpoint)).digest('hex');
 if(expectedDigest!==undefined&&(typeof expectedDigest!=='string'||!/^[a-f0-9]{64}$/.test(expectedDigest)||checkpointDigest!==expectedDigest))throw Error('Synthetic checkpoint pin mismatch');
 return {verified:true,checkpointDigest,rootHash:integrity.rootHash,steps:integrity.steps,witnessId:claims.witnessId,
  limitations:['Signature proves possession of the supplied key, not independent custody, trusted time or real execution.']};
}
export function replaySynthetic(trace,{policy}={}){
  const integrity=verifyTrace(trace);
  const target=policy===undefined?trace.policy:validatePolicy(policy);
  const simulated=compute(target,trace.steps.map(s=>s.intent));
  const divergences=[];
  for(const [i,step] of trace.steps.entries()){
    const current=simulated.steps[i];
    if(step.outcome!==current.outcome||step.stateHash!==current.stateHash){
      divergences.push({seq:i,id:step.intent.id,was:step.outcome,now:current.outcome,stateChanged:step.stateHash!==current.stateHash});
    }
  }
  return {format:'faraday-timemachine-replay',version:1,mode:'offline-no-effects',verified:integrity.verified,
    summary:{steps:trace.steps.length,divergences:divergences.length},divergences,
    finalStateHash:simulated.finalStateHash,originalRootHash:trace.rootHash,
    limitations:['No real tool re-execution or causal proof beyond this synthetic state machine.']};
}
export function diffSynthetic(before,after){
  verifyTrace(before);verifyTrace(after);
  const a=new Map(before.steps.map(x=>[x.intent.id+'#'+x.seq,x]));
  const b=new Map(after.steps.map(x=>[x.intent.id+'#'+x.seq,x]));
  const ids=[...new Set([...a.keys(),...b.keys()])].sort();
  const changed=ids.filter(id=>sha(a.get(id)||null)!==sha(b.get(id)||null)).map(id=>({id,
    before:a.get(id)?.outcome??null,after:b.get(id)?.outcome??null}));
  return {format:'faraday-timemachine-diff',version:1,mode:'offline-synthetic',changed,
    summary:{before:before.steps.length,after:after.steps.length,changed:changed.length}};
}
export function readSyntheticTrace(path){
  const st=lstatSync(path);if(!st.isFile()||st.isSymbolicLink()||st.size>512*1024)throw Error('Unsafe trace file');
  const trace=JSON.parse(readFileSync(path,'utf8'));verifyTrace(trace);return trace;
}
export function readSyntheticCheckpoint(path){
  const st=lstatSync(path);if(!st.isFile()||st.isSymbolicLink()||st.size>16*1024)throw Error('Unsafe checkpoint file');
  return JSON.parse(readFileSync(path,'utf8'));
}
export function readReplayPolicy(path){
  const st=lstatSync(path);if(!st.isFile()||st.isSymbolicLink()||st.size>64*1024)throw Error('Unsafe policy file');
  const policy=JSON.parse(readFileSync(path,'utf8'));return validatePolicy(policy);
}
