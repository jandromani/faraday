/** R13: short leases are granted by a distinct, privileged control-plane
 * PostgreSQL principal. Gateway executor cannot promote itself.
 */
export function createNativePgLeaseCoordinator({controllerPool,scope='invoice:demo'}={}){
 if(!controllerPool||typeof controllerPool.query!=='function'||scope!=='invoice:demo')
  throw Error('invalid-lease-controller');
 return {
  async claim({owner,ttlMs=1000}={}){
   if(typeof owner!=='string'||!/^gateway-[a-z0-9-]{1,30}$/.test(owner)||
    !Number.isSafeInteger(ttlMs)||ttlMs<250||ttlMs>30000)throw Error('invalid-lease-request');
   const r=await controllerPool.query(
    'SELECT faraday_secure.claim_lease($1::text,$2::text,$3::integer) AS epoch',
    [scope,owner,ttlMs]);
   const e=r.rows?.[0]?.epoch;
   if(e===null)return null; // another live leader owns the lease
   if(!/^\d{1,15}$/.test(String(e)))throw Error('invalid-lease-epoch');
   return String(e);
  }
 };
}
