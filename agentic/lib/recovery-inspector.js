/** E16: read-only recovery inspector for synthetic Secure Pilot reservations.
 * Never retries, releases, reauthorizes, or performs operations.
 */
import {DatabaseSync} from 'node:sqlite';
import {lstatSync} from 'node:fs';
const STATES=new Set(['reserved','upstream-uncertain','simulated','upstream-rejected']);
export function inspectRecovery({path,now=Date.now(),staleAfterMs=60000}={}){
  if(typeof path!=='string'||!path||!Number.isSafeInteger(now)||now<0||
     !Number.isSafeInteger(staleAfterMs)||staleAfterMs<0||staleAfterMs>30*24*3600*1000)throw Error('Invalid recovery inspection options');
  const st=lstatSync(path);
  if(!st.isFile()||st.isSymbolicLink()||st.size>100*1024*1024)throw Error('Unsafe recovery journal');
  const db=new DatabaseSync(path,{readOnly:true});
  try{
    const rows=db.prepare('SELECT operation_id,state,created_at,receipt_json FROM executions ORDER BY created_at ASC,operation_id ASC LIMIT 10001').all();
    if(rows.length>10000)throw Error('Too many operations to inspect');
    const operations=[],summary={total:0,completed:0,rejected:0,uncertain:0,staleReserved:0,freshReserved:0};
    for(const row of rows){
      if(!STATES.has(row.state)||typeof row.operation_id!=='string'||!Number.isSafeInteger(row.created_at))throw Error('Invalid journal rows');
      const ageMs=Math.max(0,now-row.created_at);summary.total++;
      if(row.state==='simulated')summary.completed++;
      else if(row.state==='upstream-rejected')summary.rejected++;
      else if(row.state==='upstream-uncertain')summary.uncertain++;
      else if(ageMs>=staleAfterMs)summary.staleReserved++;
      else summary.freshReserved++;
      if(row.state==='reserved'||row.state==='upstream-uncertain')operations.push({id:row.operation_id,state:row.state,
        ageMs,operatorAction:row.state==='reserved'?'investigate-before-retrying':'read-only-reconciliation',hasReceipt:!!row.receipt_json});
    }
    return {format:'faraday-recovery-inspection',version:1,mode:'read-only',summary,operations,
      caveat:'Stale reservation may or may not have reached the backend. Do not replay or purge automatically.'};
  }finally{db.close();}
}
