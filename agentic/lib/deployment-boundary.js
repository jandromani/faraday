/** Validate an explicit reference Docker deployment; do not claim arbitrary production isolation.
 * Input is `docker compose config --format json`, NOT hand-written YAML regexes.
 */
export class DeploymentBoundaryError extends Error{
  constructor(violations){super('unsafe-reference-deployment: '+violations.join('; '));this.violations=violations;}
}
function endpoints(service){return (service?.networks && (Array.isArray(service.networks)?service.networks:Object.keys(service.networks)))||[];}
function mounts(service){return (service?.volumes||[]).map(v=>typeof v==='string'?{source:v.split(':')[0],target:v.split(':')[1]}:{source:v.source,target:v.target});}
const unsafeDev = s => Boolean(s.devices?.length||s.volumes_from?.length||s.links?.length||s.extra_hosts?.length||s.secrets?.length||s.configs?.length||s.privileged||s.ipc==='host'||s.uts==='host');
const hasNoNewPrivileges=s=>(s.security_opt||[]).some(v=>String(v).includes('no-new-privileges:true'));
export function validateReferenceBoundary(compose){
 const errors=[];const services=compose?.services||{};const networks=compose?.networks||{};
 const requireCheck=(cond,reason)=>{if(!cond)errors.push(reason);};
 const agent=services['dummy-agent'],rogue=services['rogue-agent'],gateway=services.gateway,backend=services.backend;
 requireCheck(Object.keys(services).sort().join(',')===['backend','dummy-agent','gateway','rogue-agent'].join(','),'services:unexpected');
 requireCheck(Object.keys(networks).sort().join(',')===['agent_zone','backend_private'].join(','),'networks:unexpected');
 for(const [role,service] of Object.entries({agent,rogue,gateway,backend})){
   requireCheck(Boolean(service),`${role}:missing`);
   if(!service)continue;
   const nets=endpoints(service);
   const expected=role==='gateway'?['agent_zone','backend_private']:role==='backend'?['backend_private']:['agent_zone'];
   requireCheck(JSON.stringify([...nets].sort())===JSON.stringify([...expected].sort()),`${role}:networks`);
   requireCheck(!service.privileged && !['host','none','service:backend','container:backend'].includes(service.network_mode) && !service.pid && !unsafeDev(service),`${role}:privileged-host-mode`);
   requireCheck(!service.network_mode && !service.volumes_from?.length && !service.dns?.length && !service.dns_search?.length,`${role}:network-overrides`);
   requireCheck(!service.ports?.length && !service.expose?.some(p=>String(p).includes('0.0.0.0')),`${role}:exposure`);
   requireCheck(service.read_only===true && hasNoNewPrivileges(service) && (service.cap_drop||[]).includes('ALL'),`${role}:hardening`);
   requireCheck(Number(service.pids_limit)>0 && Number(service.pids_limit)<=128 && Number(service.mem_limit)>0,`${role}:resource-limits`);
   const volumes=mounts(service);
   if(role==='agent'||role==='rogue')requireCheck(!volumes.some(m=>['/run/faraday','/run/backend-state','/run/state'].some(prefix=>[m.target,m.source].some(x=>x===prefix||x?.startsWith(prefix+'/')))),`${role}:secret-volume`);
   if(role==='rogue')requireCheck(!volumes.some(m=>[m.target,m.source].some(x=>x==='/run/agent'||x?.startsWith('/run/agent/'))),`${role}:agent-credential-leak`);
   if(role==='backend')requireCheck(!volumes.some(m=>[m.target,m.source].some(x=>['/run/agent','/run/state'].some(prefix=>x===prefix||x?.startsWith(prefix+'/')))),`${role}:gateway-volume-leak`);
   requireCheck(!volumes.some(m=>m.target==='/var/run/docker.sock'||m.source==='/var/run/docker.sock'||m.target==='/'||m.source==='/'),`${role}:docker-socket-or-host-root`);
 }
 requireCheck(networks?.backend_private?.internal===true,'backend:network-not-internal');
 requireCheck(networks?.agent_zone?.internal===true,'agent-zone:must-be-internal');
 requireCheck(!networks?.agent_zone?.external&&!networks?.backend_private?.external,'networks:external');
 if(errors.length)throw new DeploymentBoundaryError(errors);
 return {topology:'isolated-gateway-reference',servicesChecked:4,untrustedAgentIsolated:true,credentialMountsConstrained:true};
}
