/** Explicit optional adapter execution: observations never authorize tool calls. */
import {AuthorityGate, canonical} from './authority.js';
import {validateAdapterContract} from './r4-adapter-contract.js';
export function createAuthorityMediatedAdapter({contract,gate,dispatch,onDecision}={}){
  const c=validateAdapterContract(contract);
  if(!(gate instanceof AuthorityGate)||typeof dispatch!=='function'||(onDecision!==undefined&&typeof onDecision!=='function'))
    throw Error('invalid-authority-adapter-configuration');
  const allowed=new Set(c.capabilities.map(x=>[x.tool,x.operation,x.resource].join('\0')));
  return Object.freeze({
    framework:c.framework,
    async invoke({tool,operation,resource,capability,proof}={}){
      if(!allowed.has([tool,operation,resource].join('\0')))
        throw Error('adapter-capability-not-declared');
      const decision=gate.authorize({capability,proof});
      if(decision.tool!==tool||decision.action!==operation||decision.resource!==resource)
        throw Error('adapter-authority-scope-mismatch');
      if(onDecision)await onDecision(Object.freeze({framework:c.framework,adapter:c.adapter,agent:decision.agent,tool,resource,action:operation,status:'authorized'}));
      const args=JSON.parse(canonical(decision.args).toString('utf8'));
      return dispatch(Object.freeze({agent:decision.agent,tool,resource,action:operation,args,rule:decision.rule,operationId:decision.jti}));
    }
  });
}
