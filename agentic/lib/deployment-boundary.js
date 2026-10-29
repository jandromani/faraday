/** Reference Docker Compose security contract; not a generic production sandbox validator. */
export class DeploymentBoundaryError extends Error{
 constructor(violations){super('unsafe-reference-deployment: '+violations.join('; '));this.violations=violations;}
}
function endpoints(s){return (s?.networks&&(Array.isArray(s.networks)?s.networks:Object.keys(s.networks)))||[];}
function mounts(s){return (s?.volumes||[]).map(v=>typeof v==='string'?v.split(':')[1]:v.target).filter(Boolean);}
export function validateReferenceBoundary(compose){
 const errors=[],services=compose?.services||{},networks=compose?.networks||{};
 const check=(ok,why)=>{if(!ok)errors.push(why);};
 const agents={'agent':services['dummy-agent'],'rogue':services['rogue-agent'],gateway:services.gateway,backend:services.backend};
 for(const [role,s] of Object.entries(agents)){
   check(Boolean(s),role+':missing');if(!s)continue;
   const expected=role==='gateway'?['agent_zone','backend_private']:role==='backend'?['backend_private']:['agent_zone'];
   check(JSON.stringify([...endpoints(s)].sort())===JSON.stringify([...expected].sort()),role+':networks');
   check(!s.privileged&&s.network_mode!=='host'&&!s.pid,role+':privileged-host-mode');
   check(!s.ports?.length&&!s.expose?.some(p=>String(p).includes('0.0.0.0')),role+':exposure');
   check(s.read_only===true&&(s.security_opt||[]).some(v=>String(v).includes('no-new-privileges:true'))&&(s.cap_drop||[]).includes('ALL'),role+':hardening');
   check(Number(s.pids_limit)>0&&Number(s.pids_limit)<=128&&Number(s.mem_limit)>0,role+':resource-limits');
   const vols=mounts(s);
   if(role==='agent'||role==='rogue')check(!vols.some(x=>x.startsWith('/run/faraday')||x.startsWith('/run/backend-state')||x.startsWith('/run/state')),role+':secret-volume');
   if(role==='rogue')check(!vols.some(x=>x.startsWith('/run/agent')),role+':agent-credential-leak');
   if(role==='backend')check(!vols.some(x=>x.startsWith('/run/agent')||x.startsWith('/run/state')),role+':gateway-volume-leak');
 }
 check(networks?.backend_private?.internal===true,'backend:network-not-internal');
 if(errors.length)throw new DeploymentBoundaryError(errors);
 return {topology:'isolated-gateway-reference',servicesChecked:4,untrustedAgentIsolated:true,credentialMountsConstrained:true};
}
