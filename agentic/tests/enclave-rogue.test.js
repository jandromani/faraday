import test from 'node:test';
import assert from 'node:assert/strict';
import {probeEnclave} from '../scripts/enclave-rogue.mjs';

const checks={noSecretFiles:true,sourceReadOnly:true,rootReadOnly:true,nonRoot:true,noNewPrivileges:true,noCapabilities:true};
const options={backendHost:'192.0.2.10',egressHost:'192.0.2.20',checks};
test('rogue probe checks direct IP routes and rejected gateway calls',async()=>{
  const urls=[];
  const result=await probeEnclave({...options,request:async url=>{urls.push(url);if(url.includes('gateway'))return {status:403};throw Error('unreachable');}});
  assert.equal(result.pass,true);assert.equal(urls.length,4);
  assert.match(urls[0],/192\.0\.2\.10:8099/);assert.match(urls[1],/192\.0\.2\.20:8097/);
});
test('a direct response, writable filesystem or unavailable gateway fails the probe',async()=>{
  const reachable=await probeEnclave({...options,request:async()=>({status:403})});assert.equal(reachable.pass,false);assert.equal(reachable.checks.backendDirectUnreachable,false);
  const writable=await probeEnclave({...options,checks:{...checks,sourceReadOnly:false},request:async url=>{if(url.includes('gateway'))return {status:403};throw Error('unreachable');}});assert.equal(writable.pass,false);
  const down=await probeEnclave({...options,request:async()=>{throw Error('unavailable');}});assert.equal(down.pass,false);assert.equal(down.checks.anonymousDenied,false);
  await assert.rejects(probeEnclave({...options,backendHost:'backend',request:async()=>{}}),/IPv4/);
});