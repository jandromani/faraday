import test from 'node:test';
import assert from 'node:assert/strict';
import {validateReferenceBoundary,DeploymentBoundaryError} from '../lib/deployment-boundary.js';
function fixture(){
 const base=(networks,volumes=[])=>({networks,volumes,read_only:true,privileged:false,
  cap_drop:['ALL'],security_opt:['no-new-privileges:true'],mem_limit:268435456,pids_limit:64});
 return {services:{
  'dummy-agent':base(['agent_zone'],[{target:'/app'},{target:'/run/agent'}]),
  'rogue-agent':base(['agent_zone'],[{target:'/app'}]),
  gateway:base(['agent_zone','backend_private'],[{target:'/run/faraday'},{target:'/run/state'}]),
  backend:base(['backend_private'],[{target:'/run/backend-state'}])},
  networks:{agent_zone:{internal:true},backend_private:{internal:true}}};
}
const copy=v=>structuredClone(v);
test('reference topology accepts only gateway crossing the private-network boundary',()=>{
 const report=validateReferenceBoundary(fixture());
 assert.equal(report.untrustedAgentIsolated,true);
 assert.equal(report.servicesChecked,4);
});
test('rejects an untrusted agent attached directly to backend-private network',()=>{
 const x=fixture();x.services['rogue-agent'].networks.push('backend_private');
 assert.throws(()=>validateReferenceBoundary(x),e=>e instanceof DeploymentBoundaryError&&e.violations.includes('rogue:networks'));
});
test('rejects a backend attached to the public/agent network',()=>{
 const x=fixture();x.services.backend.networks.push('agent_zone');
 assert.throws(()=>validateReferenceBoundary(x),/backend:networks/);
});
test('rejects a backend-private network accidentally made external',()=>{
 const x=fixture();x.networks.backend_private.internal=false;
 assert.throws(()=>validateReferenceBoundary(x),/backend:network-not-internal/);
});
test('rejects mounts of backend credentials into rogue agent',()=>{
 const x=fixture();x.services['rogue-agent'].volumes.push({target:'/run/faraday/backend-secret'});
 assert.throws(()=>validateReferenceBoundary(x),/rogue:secret-volume/);
});
test('rejects mounts of approved agent credentials into untrusted agent',()=>{
 const x=fixture();x.services['rogue-agent'].volumes.push({target:'/run/agent'});
 assert.throws(()=>validateReferenceBoundary(x),/rogue:agent-credential-leak/);
});
test('rejects privileged, mutable or exposed containers',()=>{
 for(const [role,prop,value] of [['backend','privileged',true],['gateway','ports',[8098]],
  ['rogue-agent','read_only',false],['dummy-agent','cap_drop',[]],['backend','pids_limit',1000]]){
   const x=fixture();x.services[role][prop]=value;
   assert.throws(()=>validateReferenceBoundary(x),DeploymentBoundaryError,`${role}/${prop}`);
  }
});
test('rejects disabled no-new-privileges or host networking',()=>{
 const a=fixture();a.services.gateway.security_opt=[];
 assert.throws(()=>validateReferenceBoundary(a),/gateway:hardening/);
 const b=fixture();b.services['dummy-agent'].network_mode='host';
 assert.throws(()=>validateReferenceBoundary(b),/agent:privileged-host-mode/);
});

for(const [what,change] of [
 ['public agent network',x=>{x.networks.agent_zone.internal=false;}],
 ['unlisted service with private network',x=>{x.services.evil={networks:['backend_private']};}],
 ['credential source alias',x=>{x.services['rogue-agent'].volumes.push({source:'/run/agent',target:'/tmp/alias'});}],
 ['Docker socket alias',x=>{x.services['rogue-agent'].volumes.push({source:'/var/run/docker.sock',target:'/tmp/sock'});}],
 ['volumes_from backend',x=>{x.services['rogue-agent'].volumes_from=['backend'];}],
 ['host extra_hosts',x=>{x.services['rogue-agent'].extra_hosts=['backend:127.0.0.1'];}],
 ['compose secrets',x=>{x.services['rogue-agent'].secrets=['backend-secret'];}],
 ['unexpected network',x=>{x.networks.extra={internal:false};}]
])test('reference contract rejects '+what,()=>{
 const x=fixture();change(x);
 assert.throws(()=>validateReferenceBoundary(x),DeploymentBoundaryError);
});
