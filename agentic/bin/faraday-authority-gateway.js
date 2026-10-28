#!/usr/bin/env node
/** Launch from a separately provisioned config, never from issuer private key files. */
import {readFileSync} from 'node:fs';
import {AuthorityGate,NonceLedger,readKeyFile} from '../lib/authority.js';
import {createAuthorityGateway} from '../lib/authority-gateway.js';
import {GraphStore} from '../lib/store.js';
const config=JSON.parse(readFileSync(process.env.FARADAY_AUTHORITY_CONFIG,'utf8'));
const keys=Object.fromEntries(Object.entries(config.issuerKeys).map(([id,path])=>[id,readKeyFile(path)]));
const agents=Object.fromEntries(Object.entries(config.agents).map(([id,path])=>[id,readKeyFile(path)]));
const ledger=new NonceLedger(config.db);
const gate=new AuthorityGate({issuerKeys:keys,registry:agents,policy:JSON.parse(readFileSync(config.policy,'utf8')),ledger});
const backendSecret=readFileSync(config.backendSecretFile,'utf8').trim();
const audit=config.graphDb?new GraphStore(config.graphDb):null;
const onDecision=audit?({status,tool})=>{audit.event({server:'faraday-authority',direction:'request',kind:'authority',operation:'execute',tool:tool??null,status});}:undefined;
const server=createAuthorityGateway({gate,backendUrl:config.backendUrl,backendSecret,onDecision});
const port=Number(process.env.PORT??8098);
server.listen(port,'0.0.0.0',()=>console.log(`FARADAY Authority Preview gateway listening on ${port}`));
const stop=()=>server.close(()=>{ledger.close();audit?.close();process.exit(0);});
process.on('SIGTERM',stop);process.on('SIGINT',stop);
