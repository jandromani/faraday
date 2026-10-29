/** R4 adapter capability contract: exact allowlists; metadata cannot grant runtime access. */
const FRAMEWORKS=new Set(['langgraph','crewai','openai-agents']);
const OPS=new Set(['read','write','execute','pay','deploy']);
// Exact qualified resources such as invoice:demo must work with real Authority scopes.
const RESOURCE=/^[a-z][a-z0-9_.:\/-]{0,127}$/;
const ID=/^[a-z][a-z0-9_-]{0,63}$/;
const isObject=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
function exact(x,keys){return isObject(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));}
function validRule(r){
 return exact(r,['tool','operation','resource'])&&typeof r.tool==='string'&&ID.test(r.tool)&&typeof r.resource==='string'&&RESOURCE.test(r.resource)&&OPS.has(r.operation);
}
export function validateAdapterContract(contract){
 if(!exact(contract,['version','framework','adapter','capabilities','mode']))throw Error('invalid-adapter-contract');
 if(contract.version!==1||!FRAMEWORKS.has(contract.framework)||typeof contract.adapter!=='string'||!ID.test(contract.adapter)||contract.mode!=='observe-only')throw Error('invalid-adapter-contract');
 if(!Array.isArray(contract.capabilities)||contract.capabilities.length>128)throw Error('invalid-adapter-capabilities');
 const seen=new Set();
 for(const r of contract.capabilities){
  if(!validRule(r))throw Error('invalid-adapter-capability');
  const key=[r.tool,r.operation,r.resource].join('\0');
  if(seen.has(key))throw Error('duplicate-adapter-capability');
  seen.add(key);
 }
 return {version:1,framework:contract.framework,adapter:contract.adapter,mode:'observe-only',capabilities:contract.capabilities.map(r=>({...r}))};
}
export function decideAdapterCapability(contract,request){
 const c=validateAdapterContract(contract);
 if(!exact(request,['tool','operation','resource'])||!validRule(request))
  return {allowed:false,reason:'invalid-request',executionAuthorized:false};
 const declared=c.capabilities.some(r=>r.tool===request.tool&&r.operation===request.operation&&r.resource===request.resource);
 return {allowed:false,reason:declared?'observation-only':'undeclared-capability',declared,executionAuthorized:false};
}
export function compareAdapterContracts(before,after){
 const a=validateAdapterContract(before),b=validateAdapterContract(after);
 if(a.framework!==b.framework||a.adapter!==b.adapter)throw Error('adapter-identity-changed');
 const key=r=>[r.tool,r.operation,r.resource].join('\0');
 const old=new Set(a.capabilities.map(key)),next=new Set(b.capabilities.map(key));
 return {adapter:a.adapter,framework:a.framework,
  added:b.capabilities.filter(r=>!old.has(key(r))),
  removed:a.capabilities.filter(r=>!next.has(key(r))),
  needsAuthorityReview:b.capabilities.some(r=>!old.has(key(r))),
  runtimePermissionGranted:false};
}
