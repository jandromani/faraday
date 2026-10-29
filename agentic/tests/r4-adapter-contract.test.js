import test from 'node:test';
import assert from 'node:assert/strict';
import {validateAdapterContract,decideAdapterCapability,compareAdapterContracts} from '../lib/r4-adapter-contract.js';
const base=()=>({version:1,framework:'langgraph',adapter:'example',mode:'observe-only',
 capabilities:[{tool:'lookup',operation:'read',resource:'documents'}]});
test('canonical adapter contracts are validated and copied',()=>{
 const x=base(),v=validateAdapterContract(x);assert.deepEqual(v,x);assert.notEqual(v.capabilities,x.capabilities);
});
test('declared capabilities remain observational; never authorize execution',()=>{
 assert.deepEqual(decideAdapterCapability(base(),{tool:'lookup',operation:'read',resource:'documents'}),
 {allowed:false,reason:'observation-only',declared:true,executionAuthorized:false});
 assert.equal(decideAdapterCapability(base(),{tool:'delete',operation:'write',resource:'documents'}).allowed,false);
});
test('added capability requires review, does not grant authority',()=>{
 const b=base();b.capabilities.push({tool:'deploy',operation:'execute',resource:'release'});
 const d=compareAdapterContracts(base(),b);
 assert.equal(d.needsAuthorityReview,true);assert.equal(d.runtimePermissionGranted,false);assert.equal(d.added.length,1);
});
for(const [title,mutate] of [
 ['unknown framework',x=>x.framework='untrusted'],
 ['active mode',x=>x.mode='execute'],
 ['extra untrusted field',x=>x.token='secret'],
 ['duplicate capability',x=>x.capabilities.push({...x.capabilities[0]})],
 ['wildcard resource',x=>x.capabilities[0].resource='*'],
 ['empty tool',x=>x.capabilities[0].tool=''],
 ['unknown operation',x=>x.capabilities[0].operation='admin'],
 ['excessive capabilities',x=>x.capabilities=Array(129).fill({tool:'lookup',operation:'read',resource:'documents'})],
 ])test('rejects '+title,()=>{const x=base();mutate(x);assert.throws(()=>validateAdapterContract(x));});
test('rejects identity switch between contract versions',()=>{
 const b=base();b.adapter='different';assert.throws(()=>compareAdapterContracts(base(),b));
});
