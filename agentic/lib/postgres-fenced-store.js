/** R7: PostgreSQL is the sole authority for SYNTHETIC backend effects.
 * The SQL driver is injected by a trusted backend (not exposed to an agent).
 * On failure/timeout, caller gets an uncertain result and must reconcile.
 */
import {digest} from './authority.js';
import {R5_APPLY_SQL,R5_COUNT_SQL} from './postgres-fencing-protocol.js';

export const R7_LOOKUP_SQL=String.raw`
SELECT payload_hash, 'simulated',
 (EXTRACT(EPOCH FROM created_at)*1000)::bigint
FROM faraday_r5_effects
WHERE scope=:'scope' AND operation_id=:'operation';
`;

const operationId=id=>typeof id==='string'&&/^[-_a-zA-Z0-9]{20,128}$/.test(id);
const validBody=body=>body&&body.tool==='pay_invoice'&&body.resource==='invoice:demo'&&
 body.action==='pay'&&operationId(body.operationId)&&body.args&&
 typeof body.args==='object'&&!Array.isArray(body.args)&&
 Object.keys(body.args).sort().join('|')==='amount_cents|currency|recipient'&&
 Number.isSafeInteger(body.args.amount_cents)&&body.args.amount_cents>=1&&
 body.args.amount_cents<=20000&&body.args.currency==='EUR'&&
 body.args.recipient==='supplier_demo';

export class PostgresFencedSyntheticStore {
 constructor({executeSql,scope='invoice:demo'}={}){
  if(typeof executeSql!=='function'||scope!=='invoice:demo')throw Error('invalid-fenced-store');
  this.executeSql=executeSql;this.scope=scope;this.fenced=true;
 }
 async apply(body){
  if(!validBody(body)||!/^gateway-[a-z0-9-]{1,30}$/.test(body.fenceOwner??'')||
     !/^[1-9][0-9]{0,14}$/.test(body.fenceEpoch??''))return {http:403,status:'fixture-denied'};
  const requestHash=digest({tool:body.tool,resource:body.resource,action:body.action,args:body.args});
  const variables={scope:this.scope,owner:body.fenceOwner,epoch:body.fenceEpoch,
   operation:body.operationId,digest:Buffer.from(requestHash,'base64url').toString('hex')};
  let outcome;
  try{outcome=(await this.executeSql(R5_APPLY_SQL,variables)).trim();}
  catch{return {http:503,status:'storage-unavailable'};}
  if(outcome==='applied'||outcome==='duplicate')return {
   http:200,status:'simulated',duplicate:outcome==='duplicate',
   operationId:body.operationId,requestHash};
  if(outcome==='fenced')return {http:409,status:'fenced'};
  if(outcome==='conflict'){
   // Concurrent READ COMMITTED statements can see ON CONFLICT before their
   // statement snapshot sees the winning row. Reconcile AFTER the statement.
   // Never repeat the insert; a matching committed hash is an idempotent replay.
   try{
    const committed=await this.get(body.operationId);
    if(committed?.request_hash===requestHash)return {
     http:200,status:'simulated',duplicate:true,operationId:body.operationId,requestHash};
   }catch{return {http:503,status:'storage-unavailable'};}
   return {http:409,status:'conflicting-operation'};
  }
  return {http:503,status:'storage-unavailable'};
 }
 async get(id){
  if(!operationId(id))return null;
  let out;
  try{out=(await this.executeSql(R7_LOOKUP_SQL,{scope:this.scope,operation:id})).trim();}
  catch{throw Error('fenced-storage-unavailable');}
  if(!out)return null;
  const fields=out.split('|');
  if(fields.length!==3||!/^[a-f0-9]{64}$/.test(fields[0])||
     fields[1]!=='simulated'||!/^[0-9]{13,16}$/.test(fields[2]))throw Error('invalid-fenced-record');
  return {request_hash:Buffer.from(fields[0],'hex').toString('base64url'),status:'simulated',occurred_at:Number(fields[2])};
 }
 async count(){
  const result=(await this.executeSql(R5_COUNT_SQL,{scope:this.scope})).trim();
  if(!/^[0-9]{1,12}$/.test(result))throw Error('invalid-fenced-count');
  return Number(result);
 }
 close(){}
}
