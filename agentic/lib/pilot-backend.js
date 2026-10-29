/** Durable synthetic backend: never performs transfers or real external actions. */
import http from 'node:http';
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,lstatSync,chmodSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {digest} from './authority.js';
import {signBackendAttestation} from './backend-attestation.js';
import {readJson} from './authority-gateway.js';
const respond=(r,status,body)=>{const bytes=Buffer.from(JSON.stringify(body));r.writeHead(status,{'content-type':'application/json','content-length':bytes.length,'cache-control':'no-store'});r.end(bytes);};
export class DurableSyntheticStore {
  constructor(path){
    mkdirSync(dirname(resolve(path)),{recursive:true,mode:0o700});
    try{const s=lstatSync(path);if(!s.isFile()||s.isSymbolicLink())throw Error('unsafe-database-path');}catch(e){if(e.code!=='ENOENT')throw e;}
    this.db=new DatabaseSync(path);
    this.db.exec('PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS synthetic_actions (operation_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, status TEXT NOT NULL, occurred_at INTEGER NOT NULL)');
    if(process.platform!=='win32')chmodSync(path,0o600);
    this.insert=this.db.prepare('INSERT INTO synthetic_actions (operation_id,request_hash,status,occurred_at) VALUES (?,?,?,?)');
    this.lookup=this.db.prepare('SELECT request_hash,status,occurred_at FROM synthetic_actions WHERE operation_id=?');
  }
  apply(body){
    if(body.tool!=='pay_invoice'||body.resource!=='invoice:demo'||body.action!=='pay'||
       typeof body.operationId!=='string'||!/^[-_a-zA-Z0-9]{20,128}$/.test(body.operationId)||
       !body.args||Object.keys(body.args).sort().join('|')!=='amount_cents|currency|recipient'||
       !Number.isSafeInteger(body.args.amount_cents)||body.args.amount_cents<1||body.args.amount_cents>20_000||
       body.args.currency!=='EUR'||body.args.recipient!=='supplier_demo')return {http:403,status:'fixture-denied'};
    const requestHash=digest({tool:body.tool,resource:body.resource,action:body.action,args:body.args});
    try{
      this.insert.run(body.operationId,requestHash,'simulated',Date.now());
      return {http:200,status:'simulated',duplicate:false,operationId:body.operationId,requestHash};
    }catch{
      const existing=this.lookup.get(body.operationId);
      if(existing?.request_hash===requestHash)return {http:200,status:'simulated',duplicate:true,operationId:body.operationId,requestHash};
      return {http:409,status:'conflicting-operation'};
    }
  }
  get(id){return this.lookup.get(id)??null;}
  count(){return this.db.prepare('SELECT count(*) AS n FROM synthetic_actions').get().n;}
  close(){this.db.close();}
}
export function createDurableSyntheticBackend({secret,secretProvider=null,store,attestationPrivatePem}){
  if(((!secretProvider && (typeof secret!=='string'||secret.length<32)) || (secretProvider && typeof secretProvider!=='function'))||!store||typeof store.apply!=='function'||!attestationPrivatePem)throw Error('Synthetic backend requires secret, durable store and independent signing key');
  return http.createServer(async(req,res)=>{
    if(req.url==='/healthz'&&req.method==='GET')return respond(res,200,{status:'ok'});
    if(!['/internal/execute','/internal/status'].includes(req.url)||req.method!=='POST')return respond(res,404,{error:'not-found'});
    let currentSecret;
    try{currentSecret=secretProvider?await secretProvider():secret;}catch{return respond(res,503,{error:'credential-unavailable'});}
    if(typeof currentSecret!=='string'||currentSecret.length<32)return respond(res,503,{error:'credential-unavailable'});
    if(req.headers.authorization!==`Bearer ${currentSecret}`)return respond(res,401,{error:'unauthorized'});
    try{
      const body=await readJson(req);
      if(req.url==='/internal/status'){
        if(!body||Object.keys(body).sort().join('|')!=='operationId|requestHash')return respond(res,400,{error:'invalid-status-request'});
        if(typeof body.operationId!=='string'||typeof body.requestHash!=='string')return respond(res,400,{error:'invalid-status-request'});
        const record=store.get(body.operationId);
        if(!record||record.request_hash!==body.requestHash||record.status!=='simulated')return respond(res,404,{error:'operation-not-found'});
        const attestation=signBackendAttestation({privatePem:attestationPrivatePem,claims:{version:1,operationId:body.operationId,requestHash:record.request_hash,status:'simulated',recordedAt:record.occurred_at}});
        return respond(res,200,{status:'simulated',operationId:body.operationId,requestHash:record.request_hash,attestation});
      }
      const result=store.apply(body);
      if(result.http!==200)return respond(res,result.http,result);
      const record=store.get(result.operationId);
      const attestation=signBackendAttestation({privatePem:attestationPrivatePem,claims:{version:1,operationId:result.operationId,requestHash:result.requestHash,status:'simulated',recordedAt:record.occurred_at}});
      return respond(res,result.http,{...result,attestation});
    }
    catch{return respond(res,400,{error:'invalid-request'});}
  });
}
