/** Only synthetic fixtures: no real keys, clients, bank APIs or money. */
import {newIdentity,createIntent,createExecution,AuthorityIssuer,AuthorityGate,NonceLedger} from './authority.js';
import {randomBytes} from 'node:crypto';
import {join} from 'node:path';
export const AGENT='faraday://lab/finance';
export const TOOL='pay_invoice';
export const RESOURCE='invoice:demo';
export const ACTION='pay';
export const ARGS=Object.freeze({amount_cents:9500,currency:'EUR',recipient:'supplier_demo'});
export const POLICY={version:1,mode:'enforce',rules:[{id:'fake-invoice-only',agent:AGENT,tool:TOOL,
  resource:RESOURCE,action:ACTION,required:['amount_cents','currency','recipient'],exactKeys:true,
  equal:{currency:'EUR',recipient:'supplier_demo'},maxAmountCents:20000}]};
export function fixture(root,{now}={}){
  const issuer=newIdentity(),agent=newIdentity(),registry={[AGENT]:agent.publicPem};
  const issuerLedger=new NonceLedger(join(root,'issuer.sqlite'));
  const gatewayLedger=new NonceLedger(join(root,'gateway.sqlite'));
  const opts={...(now===undefined?{}:{now:()=>now})};
  const iss=new AuthorityIssuer({issuerPrivatePem:issuer.privatePem,kid:'lab-issuer',registry,policy:POLICY,ledger:issuerLedger,...opts});
  const gate=new AuthorityGate({issuerKeys:{'lab-issuer':issuer.publicPem},registry,policy:POLICY,ledger:gatewayLedger,...opts});
  const timestamp=now??Math.floor(Date.now()/1000);
  const intent=createIntent({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,
    agentPrivatePem:agent.privatePem,now:timestamp});
  const capability=iss.issue(intent);
  const proof=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,
    capability,agentPrivatePem:agent.privatePem,now:timestamp});
  const backendSecret=randomBytes(32).toString('hex');
  return {issuer,agent,registry,issuerLedger,gatewayLedger,iss,gate,intent,capability,proof,backendSecret,
    close:()=>{issuerLedger.close();gatewayLedger.close();}};
}
