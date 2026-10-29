import {test} from 'node:test';import assert from 'node:assert/strict';
import {createFailClosedGatewayPolicyPort} from '../lib/gateway-policy-port.js';
test('External policy adapter denies errors, timeouts and malformed verdicts',async()=>{
 const err=createFailClosedGatewayPolicyPort({authorize:()=>{throw Error('outage');}});
 assert.equal((await err({agent:'a',method:'tools/call',resource:'b'})).allowed,false);
 const timeout=createFailClosedGatewayPolicyPort({authorize:()=>new Promise(()=>{}),timeoutMs:10});
 assert.equal((await timeout({agent:'a',method:'tools/call',resource:'b'})).allowed,false);
 const invalid=createFailClosedGatewayPolicyPort({authorize:()=>({allowed:true})});
 assert.equal((await invalid({agent:'a',method:'tools/call',resource:'b'})).allowed,false);
});
test('External policy port sends fingerprints, not raw identity or resource',async()=>{
 let observed;
 const authorize=createFailClosedGatewayPolicyPort({authorize:s=>(observed=s,{decision:'allow'})});
 assert.equal((await authorize({agent:'secret-agent',method:'tools/call',resource:'secret-resource'})).allowed,true);
 assert.doesNotMatch(JSON.stringify(observed),/secret-agent|secret-resource/);
 assert.equal((await authorize({agent:'secret-agent',method:'resources/read',resource:'secret-resource'})).allowed,false);
});
