#!/usr/bin/env node
import {mkdirSync,writeFileSync,existsSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {randomBytes} from 'node:crypto';
import {newIdentity,createIntent,AuthorityIssuer,NonceLedger} from '../lib/authority.js';
import {AGENT,TOOL,RESOURCE,ACTION,ARGS,POLICY} from '../lib/authority-fixture.js';
const root=resolve(process.argv[2]||'.faraday/pilot-lab');
if(existsSync(root))throw Error('Refusing to overwrite lab data');
const gw=join(root,'gateway'),agentDir=join(root,'agent'),issuerDir=join(root,'issuer'),backendDir=join(root,'backend'),state=join(root,'gateway-state');
for(const p of [root,gw,agentDir,issuerDir,backendDir,state])mkdirSync(p,{recursive:true,mode:0o700});
const privateWrite=(path,value)=>writeFileSync(path,value,{flag:'wx',mode:0o600});
const issuer=newIdentity(),agent=newIdentity(),receipt=newIdentity(),backendKey=newIdentity(),serviceSecret=randomBytes(40).toString('base64url');
privateWrite(join(issuerDir,'issuer-private.pem'),issuer.privatePem);
privateWrite(join(agentDir,'agent-private.pem'),agent.privatePem);
privateWrite(join(agentDir,'receipt.pub'),receipt.publicPem);
privateWrite(join(agentDir,'backend.pub'),backendKey.publicPem);
privateWrite(join(backendDir,'backend-attestation-private.pem'),backendKey.privatePem);
privateWrite(join(gw,'backend.pub'),backendKey.publicPem);
privateWrite(join(gw,'issuer.pub'),issuer.publicPem);
privateWrite(join(gw,'agent.pub'),agent.publicPem);
privateWrite(join(gw,'receipt-private.pem'),receipt.privatePem);
privateWrite(join(gw,'policy.json'),JSON.stringify(POLICY));
privateWrite(join(gw,'backend-secret'),serviceSecret);
const issuerLedger=new NonceLedger(join(issuerDir,'issue.sqlite'));
try{
  const authority=new AuthorityIssuer({issuerPrivatePem:issuer.privatePem,kid:'pilot-issuer',registry:{[AGENT]:agent.publicPem},policy:POLICY,ledger:issuerLedger});
  const intent=createIntent({agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS,agentPrivatePem:agent.privatePem});
  const capability=authority.issue(intent,{ttl:300});
  privateWrite(join(agentDir,'capability.json'),JSON.stringify({capability}));
}finally{issuerLedger.close();}
privateWrite(join(gw,'pilot.json'),JSON.stringify({issuerKeys:{'pilot-issuer':'/run/faraday/issuer.pub'},
  agents:{[AGENT]:'/run/faraday/agent.pub'},policy:'/run/faraday/policy.json',
  backendSecretFile:'/run/faraday/backend-secret',receiptPrivateFile:'/run/faraday/receipt-private.pem',backendPublicFile:'/run/faraday/backend.pub',
  nonceDb:'/run/state/nonce.sqlite',journalDb:'/run/state/journal.sqlite',backendUrl:'http://backend:8099/internal/execute'}));
console.log(JSON.stringify({kind:'disposable-v095',root,issuerPrivateKeyMountedToGateway:false,
  agentBackendCredentialMounted:false,realSideEffects:false}));
