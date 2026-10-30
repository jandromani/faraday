/** R12 native PostgreSQL protocol adapter.
 * SQL is fixed and fully parameterized. MCP untrusted inputs cannot supply SQL.
 * The effect role NEVER receives the separate epoch-promotion connection.
 * PostgreSQL runtime dependency is intentionally optional at this stage to
 * preserve the verified offline/air-gapped 0.99.8 package workflow.
 */
import {R5_APPLY_SQL,R5_COUNT_SQL,R5_TAKEOVER_SQL,R5_FENCING_SCHEMA} from './postgres-fencing-protocol.js';
import {R7_LOOKUP_SQL} from './postgres-fenced-store.js';

const name=s=>typeof s==='string'&&/^[a-zA-Z0-9:_-]{1,100}$/.test(s);
const op=s=>typeof s==='string'&&/^[-_a-zA-Z0-9]{20,128}$/.test(s);
const hex=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
const epoch=s=>typeof s==='string'&&/^[1-9][0-9]{0,14}$/.test(s);
const scope='invoice:demo';
function values(v,keys){
 if(!v||typeof v!=='object'||Object.keys(v).sort().join('|')!==[...keys].sort().join('|'))
  throw Error('invalid-native-pg-parameters');
 return keys.map(k=>v[k]);
}
function trustedPool(pool){
 if(!pool||typeof pool.query!=='function')throw Error('native-pg-pool-required');
 return pool;
}
export function createNativePgFencedExecutor({pool}={}){
 const p=trustedPool(pool);
 return async(stmt,params)=>{
  if(stmt===R5_APPLY_SQL){
   const [s,owner,e,operation,digest]=values(params,['scope','owner','epoch','operation','digest']);
   if(s!==scope||!name(owner)||!owner.startsWith('gateway-')||!epoch(e)||!op(operation)||!hex(digest))
    throw Error('invalid-native-pg-parameters');
   const result=await p.query(
    'SELECT faraday_secure.apply_effect($1::text,$2::text,$3::bigint,$4::text,$5::text) AS result',
    [s,owner,e,operation,digest]);
   const status=result.rows?.[0]?.result;
   if(!['applied','duplicate','fenced','conflict'].includes(status))throw Error('invalid-native-pg-response');
   return status;
  }
  if(stmt===R7_LOOKUP_SQL){
   const [s,operation]=values(params,['scope','operation']);
   if(s!==scope||!op(operation))throw Error('invalid-native-pg-parameters');
   const result=await p.query(
    'SELECT payload_hash,record_state,occurred_at_ms FROM faraday_secure.lookup_effect($1::text,$2::text)',
    [s,operation]);
   if(result.rows.length===0)return '';
   if(result.rows.length!==1)throw Error('invalid-native-pg-response');
   const r=result.rows[0];
   if(!hex(r.payload_hash)||r.record_state!=='simulated'||!/^\d{13,16}$/.test(String(r.occurred_at_ms)))
    throw Error('invalid-native-pg-response');
   return [r.payload_hash,r.record_state,r.occurred_at_ms].join('|');
  }
  if(stmt===R5_COUNT_SQL){
   const [s]=values(params,['scope']);if(s!==scope)throw Error('invalid-native-pg-parameters');
   const result=await p.query('SELECT faraday_secure.count_effects($1::text) AS count',[s]);
   if(!/^\d{1,12}$/.test(String(result.rows?.[0]?.count)))throw Error('invalid-native-pg-response');
   return String(result.rows[0].count);
  }
  // Never accept schema mutation or leader promotion from backend effect role.
  if(stmt===R5_TAKEOVER_SQL||stmt===R5_FENCING_SCHEMA)throw Error('forbidden-backend-control-statement');
  throw Error('unsupported-native-pg-statement');
 };
}
export function createNativePgPromotion({pool}={}){
 const p=trustedPool(pool);
 return async({scope:s,owner})=>{
  if(s!==scope||!name(owner)||!owner.startsWith('gateway-'))throw Error('invalid-promotion');
  const result=await p.query(
   'SELECT faraday_secure.promote($1::text,$2::text) AS epoch',[s,owner]);
  if(!/^\d{1,15}$/.test(String(result.rows?.[0]?.epoch)))throw Error('invalid-promotion-result');
  return String(result.rows[0].epoch);
 };
}
/** Production helper: require explicit TLS CA and hostname verification.
 * Only tests may pass a caller-created pool with loopback plain TCP.
 */
export async function createTlsVerifiedNativePgPool({host,port=5432,database,user,password,ca,max=5}={}){
 if(typeof host!=='string'||!host||host==='localhost'||host==='127.0.0.1'||
  !Number.isSafeInteger(port)||port<1||port>65535||
  ![database,user,password,ca].every(x=>typeof x==='string'&&x.length>0)||
  max<1||max>20||!Number.isSafeInteger(max))throw Error('native-pg-TLS-and-credentials-required');
 const {Pool}=await import('pg');
 return new Pool({host,port,database,user,password,max,
  connectionTimeoutMillis:5000,idleTimeoutMillis:10000,
  ssl:{ca,rejectUnauthorized:true,servername:host}});
}
