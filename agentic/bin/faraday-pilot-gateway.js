#!/usr/bin/env node
/** Experimental secured MCP pilot. Network controls must be configured by operator. */
import {readFileSync} from 'node:fs';
import {AuthorityGate,NonceLedger,readKeyFile} from '../lib/authority.js';
import {createSecurePilotGateway} from '../lib/pilot-mcp.js';
import {ExecutionJournal} from '../lib/pilot-receipts.js';
const cfg=JSON.parse(readFileSync(process.env.FARADAY_PILOT_CONFIG,'utf8'));
const keys=Object.fromEntries(Object.entries(cfg.issuerKeys).map(([id,path])=>[id,readKeyFile(path)]));
const registry=Object.fromEntries(Object.entries(cfg.agents).map(([id,path])=>[id,readKeyFile(path)]));
const ledger=new NonceLedger(cfg.nonceDb);
const journal=new ExecutionJournal(cfg.journalDb);
const gate=new AuthorityGate({issuerKeys:keys,registry,policy:JSON.parse(readFileSync(cfg.policy,'utf8')),ledger});
const server=createSecurePilotGateway({gate,backendUrl:cfg.backendUrl,
  backendSecret:readFileSync(cfg.backendSecretFile,'utf8').trim(),journal,
  receiptPrivatePem:readKeyFile(cfg.receiptPrivateFile,{privateKey:true})});
server.listen(Number(process.env.PORT||8098),'0.0.0.0',()=>console.log('FARADAY v0.95 pilot gateway'));
const stop=()=>server.close(()=>{ledger.close();journal.close();process.exit(0);});
process.on('SIGTERM',stop);process.on('SIGINT',stop);
