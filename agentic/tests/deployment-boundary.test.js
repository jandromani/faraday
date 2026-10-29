import test from 'node:test';import assert from 'node:assert/strict';
import {validateReferenceBoundary,DeploymentBoundaryError} from '../lib/deployment-boundary.js';
function make(){
 const s=(networks,volumes=[])=>({networks,volumes,read_only:true,cap_drop:['ALL'],security_opt:['no-new-privileges:true'],mem_limit:268435456,pids_limit:64});
 return {services:{'dummy-agent':s(['agent_zone'],[{target:'/app'},{target:'/run/agent'}]),'rogue-agent':s(['agent_zone'],[{target:'/app'}]),gateway:s(['backend_private','agent_zone'],[{target:'/run/faraday'}]),backend:s(['backend_private'],[{target:'/run/backend-state'}])},networks:{agent_zone:{},backend_private:{internal:true}}};
}
test('accept reference-only gateway isolation',()=>{assert.equal(validateReferenceBoundary(make()).servicesChecked,4);});
test('deny rogue agent backend network',()=>{const x=make();x.services['rogue-agent'].networks.push('backend_private');assert.throws(()=>validateReferenceBoundary(x),/rogue:networks/);});
test('deny backend on agent zone',()=>{const x=make();x.services.backend.networks.push('agent_zone');assert.throws(()=>validateReferenceBoundary(x),/backend:networks/);});
test('deny private network configured as public',()=>{const x=make();x.networks.backend_private.internal=false;assert.throws(()=>validateReferenceBoundary(x),/backend:network-not-internal/);});
test('deny rogue agent backend secret mount',()=>{const x=make();x.services['rogue-agent'].volumes.push({target:'/run/faraday/backend-secret'});assert.throws(()=>validateReferenceBoundary(x),/rogue:secret-volume/);});
test('deny rogue agent receiving authorized agent key',()=>{const x=make();x.services['rogue-agent'].volumes.push({target:'/run/agent'});assert.throws(()=>validateReferenceBoundary(x),/rogue:agent-credential-leak/);});
test('deny privilege escalation, exposed ports or mutable filesystem',()=>{
 for(const [role,property,value] of [['backend','privileged',true],['gateway','ports',[8098]],['rogue-agent','read_only',false],['dummy-agent','cap_drop',[]],['backend','pids_limit',1000]]){
 const x=make();x.services[role][property]=value;assert.throws(()=>validateReferenceBoundary(x),DeploymentBoundaryError);
 }
});
test('deny host networking and missing no-new-privileges',()=>{const a=make();a.services.gateway.security_opt=[];assert.throws(()=>validateReferenceBoundary(a),/gateway:hardening/);const b=make();b.services['dummy-agent'].network_mode='host';assert.throws(()=>validateReferenceBoundary(b),/agent:privileged-host-mode/);});
