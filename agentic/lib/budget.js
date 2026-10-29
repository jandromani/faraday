/** Single-node SQLite quota, fail closed. Not a distributed rate limit. */
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,lstatSync,chmodSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {AuthorityError} from './authority.js';
export class LocalBudget{
 constructor(path,{limits={},organizationLimits={},agentOrganizations={},now=()=>Date.now()}={}){
  if([limits,organizationLimits,agentOrganizations].some(value=>!value||typeof value!=='object'||Array.isArray(value))||typeof now!=='function')throw Error('invalid-budget-limits');
  for(const [name,rule] of [...Object.entries(limits),...Object.entries(organizationLimits)])if(!name||!rule||typeof rule!=='object'||Array.isArray(rule)||!Number.isSafeInteger(rule.maxCalls)||rule.maxCalls<0||rule.maxCalls>100000||!Number.isSafeInteger(rule.windowMs)||rule.windowMs<1000)throw Error('invalid-budget-rule');
  const grouped=Object.keys(organizationLimits).length>0;
  if(Object.entries(agentOrganizations).some(([agent,organization])=>!Object.hasOwn(limits,agent)||typeof organization!=='string'||!Object.hasOwn(organizationLimits,organization))||
   (grouped&&Object.keys(limits).some(agent=>!Object.hasOwn(agentOrganizations,agent)))||(!grouped&&Object.keys(agentOrganizations).length))throw Error('invalid-budget-organizations');
  mkdirSync(dirname(resolve(path)),{recursive:true,mode:0o700});
  try{const stat=lstatSync(path);if(!stat.isFile()||stat.isSymbolicLink())throw Error('unsafe-budget-db');}catch(e){if(e.code!=='ENOENT')throw e;}
  this.db=new DatabaseSync(path);this.limits=Object.fromEntries(Object.entries(limits).map(([name,rule])=>[name,{...rule}]));
  this.organizationLimits=Object.fromEntries(Object.entries(organizationLimits).map(([name,rule])=>[name,{...rule}]));this.agentOrganizations={...agentOrganizations};this.now=now;
    this.db.exec("PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS usage(agent TEXT NOT NULL,window_id INTEGER NOT NULL,calls INTEGER NOT NULL,PRIMARY KEY(agent,window_id)); CREATE TABLE IF NOT EXISTS budget_clock(agent TEXT PRIMARY KEY,last_seen_ms INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS organization_usage(organization TEXT NOT NULL,window_id INTEGER NOT NULL,calls INTEGER NOT NULL,PRIMARY KEY(organization,window_id)); CREATE TABLE IF NOT EXISTS organization_clock(organization TEXT PRIMARY KEY,last_seen_ms INTEGER NOT NULL);");
  if(process.platform!=='win32')chmodSync(path,0o600);
 }
 consume(agent){
    const rule=Object.hasOwn(this.limits,agent)?this.limits[agent]:null;if(!rule)throw new AuthorityError('no-budget-policy');
  const now=this.now();if(!Number.isSafeInteger(now)||now<0)throw new AuthorityError('invalid-budget-clock');
  const windowId=Math.floor(now/rule.windowMs);
  try{
   this.db.exec('BEGIN IMMEDIATE');
    const last=this.db.prepare('SELECT last_seen_ms FROM budget_clock WHERE agent=?').get(agent);
    if(last&&now<last.last_seen_ms)throw new AuthorityError('budget-clock-rollback');
    this.db.prepare('INSERT INTO budget_clock(agent,last_seen_ms) VALUES(?,?) ON CONFLICT(agent) DO UPDATE SET last_seen_ms=excluded.last_seen_ms').run(agent,now);
   this.db.prepare('INSERT OR IGNORE INTO usage(agent,window_id,calls) VALUES (?,?,0)').run(agent,windowId);
   const r=this.db.prepare('UPDATE usage SET calls=calls+1 WHERE agent=? AND window_id=? AND calls<?').run(agent,windowId,rule.maxCalls);
   if(r.changes!==1){this.db.exec('ROLLBACK');throw new AuthorityError('budget-exhausted');}
  const remaining=rule.maxCalls-this.db.prepare('SELECT calls FROM usage WHERE agent=? AND window_id=?').get(agent,windowId).calls;
  let organizationRemaining;
  if(Object.hasOwn(this.agentOrganizations,agent)){
   const organization=this.agentOrganizations[agent],orgRule=this.organizationLimits[organization],orgWindow=Math.floor(now/orgRule.windowMs);
   const lastOrg=this.db.prepare('SELECT last_seen_ms FROM organization_clock WHERE organization=?').get(organization);
   if(lastOrg&&now<lastOrg.last_seen_ms)throw new AuthorityError('budget-clock-rollback');
   this.db.prepare('INSERT INTO organization_clock(organization,last_seen_ms) VALUES(?,?) ON CONFLICT(organization) DO UPDATE SET last_seen_ms=excluded.last_seen_ms').run(organization,now);
   this.db.prepare('INSERT OR IGNORE INTO organization_usage(organization,window_id,calls) VALUES (?,?,0)').run(organization,orgWindow);
   const updated=this.db.prepare('UPDATE organization_usage SET calls=calls+1 WHERE organization=? AND window_id=? AND calls<?').run(organization,orgWindow,orgRule.maxCalls);
   if(updated.changes!==1)throw new AuthorityError('organization-budget-exhausted');
   organizationRemaining=orgRule.maxCalls-this.db.prepare('SELECT calls FROM organization_usage WHERE organization=? AND window_id=?').get(organization,orgWindow).calls;
  }
   this.db.exec('COMMIT');
  return {allowed:true,remaining,...(organizationRemaining===undefined?{}:{organizationRemaining})};
  }catch(e){try{this.db.exec('ROLLBACK');}catch{}if(e instanceof AuthorityError)throw e;throw new AuthorityError('budget-storage-unavailable');}
 }
 close(){this.db.close();}
}
