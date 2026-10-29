#!/usr/bin/env node
/** Experimental secured MCP pilot. Network controls must be configured by operator. */
import {readFileSync} from 'node:fs';
import {AuthorityGate,NonceLedger,readKeyFile} from '../lib/authority.js';
import {createSecurePilotGateway} from '../lib/pilot-mcp.js';
import {ExecutionJournal} from '../lib/pilot-receipts.js';
import {LocalSentinel} from '../lib/sentinel.js';
import {LocalBudget} from '../lib/budget.js';
import {PinnedOAuthResource} from '../lib/mcp-oauth-resource.js';
const cfg=JSON.parse(readFileSync(process.env.FARADAY_PILOT_CONFIG,'utf8'));
const keys=Object.fromEntries(Object.entries(cfg.issuerKeys).map(([id,path])=>[id,readKeyFile(path)]));
const registry=Object.fromEntries(Object.entries(cfg.agents).map(([id,path])=>[id,readKeyFile(path)]));
const ledger=new NonceLedger(cfg.nonceDb);
const journal=new ExecutionJournal(cfg.journalDb);
const sentinel=cfg.sentinelDb?new LocalSentinel(cfg.sentinelDb,{threshold:cfg.sentinelThreshold??5}):null;
const budget=cfg.budgetDb?new LocalBudget(cfg.budgetDb,{limits:cfg.budgets??{}}):null;
const approvalConfig=cfg.approverKeys?{approverKeys:Object.fromEntries(Object.entries(cfg.approverKeys).map(([id,x])=>[id,{publicPem:readKeyFile(x.publicKeyFile),role:x.role}])),quorum:cfg.approvalQuorum??2,requiredRoles:cfg.requiredApprovalRoles??[]}:null;
const gate=new AuthorityGate({issuerKeys:keys,registry,policy:JSON.parse(readFileSync(cfg.policy,'utf8')),ledger});
const oauthResource=cfg.oauthResource?new PinnedOAuthResource({
  issuer:cfg.oauthResource.issuer,resource:cfg.oauthResource.resource,
  authorizationServers:cfg.oauthResource.authorizationServers,
  publicJwks:JSON.parse(readFileSync(cfg.oauthResource.publicJwksFile,'utf8')).keys,
  readScope:cfg.oauthResource.readScope,executeScope:cfg.oauthResource.executeScope
}):null;
const server=createSecurePilotGateway({gate,backendUrl:cfg.backendUrl,
  backendSecret:readFileSync(cfg.backendSecretFile,'utf8').trim(),journal,
  receiptPrivatePem:readKeyFile(cfg.receiptPrivateFile,{privateKey:true}),backendPublicPem:readKeyFile(cfg.backendPublicFile),approvalConfig,sentinel,budget,oauthResource});
server.listen(Number(process.env.PORT||8098),'0.0.0.0',()=>console.log('FARADAY v0.95 pilot gateway'));
const stop=()=>server.close(()=>{ledger.close();journal.close();sentinel?.close();budget?.close();process.exit(0);});
process.on('SIGTERM',stop);process.on('SIGINT',stop);
