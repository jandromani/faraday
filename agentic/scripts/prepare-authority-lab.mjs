#!/usr/bin/env node
/** Generate disposable, unique synthetic lab identities; refuse to overwrite. */
import {mkdirSync,writeFileSync,existsSync,chmodSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {randomBytes} from 'node:crypto';
import {newIdentity,createIntent,createExecution,AuthorityIssuer,NonceLedger} from '../lib/authority.js';
import {AGENT,TOOL,RESOURCE,ACTION,ARGS,POLICY} from '../lib/authority-fixture.js';
const dir=resolve(process.argv[2]||'.faraday/authority-lab');
if(existsSync(dir))throw Error('Refusing to overwrite an existing lab; choose a fresh path');
const agentDir=join(dir,'agent'),gwDir=join(dir,'gateway'),issuerDir=join(dir,'issuer');
for(const d of [dir,agentDir,gwDir,issuerDir])mkdirSync(d,{recursive:true,mode:0o700});
const privateFile=(name,content)=>writeFileSync(name,content,{mode:0o600,flag:'wx'});
const issuer=newIdentity(),agent=newIdentity();
privateFile(join(issuerDir,'issuer-private.pem'),issuer.privatePem);
privateFile(join(agentDir,'agent-private.pem'),agent.privatePem);
privateFile(join(gwDir,'issuer.pub'),issuer.publicPem);
privateFile(join(gwDir,'agent.pub'),agent.publicPem);
privateFile(join(gwDir,'policy.json'),JSON.stringify(POLICY));
const backendSecret=randomBytes(40).toString('base64url');
privateFile(join(gwDir,'backend-secret'),backendSecret);
const ledger=new NonceLedger(join(issuerDir,'ledger.sqlite'));
try{
  const now=Math.floor(Date.now()/1000);
  const iss=new AuthorityIssuer({issuerPrivatePem:issuer.privatePem,kid:'lab-issuer',registry:{[AGENT]:agent.publicPem},policy:POLICY,ledger});
  const intent=createIntent({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,agentPrivatePem:agent.privatePem,now,ttl:30});
  const capability=iss.issue(intent,{ttl:300});
  const proof=createExecution({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,capability,agentPrivatePem:agent.privatePem,now,ttl:30});
  privateFile(join(agentDir,'request.json'),JSON.stringify({capability,proof}));
}finally{ledger.close();}
privateFile(join(gwDir,'gateway.json'),JSON.stringify({issuerKeys:{'lab-issuer':'/run/faraday/issuer.pub'},
  agents:{[AGENT]:'/run/faraday/agent.pub'},policy:'/run/faraday/policy.json',
  backendSecretFile:'/run/faraday/backend-secret',db:'/tmp/authority-ledger.sqlite',graphDb:'/tmp/authority-graph.sqlite',
  backendUrl:'http://backend:8099/internal/execute'}));
console.log(JSON.stringify({kind:'disposable-synthetic-lab',dir,expiresInSeconds:30,
  security:'Issuer private key is not mounted into gateway; only agent request proof is mounted to agent. Start docker compose immediately.'}));
