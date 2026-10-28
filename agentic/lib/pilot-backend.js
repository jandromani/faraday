/** Durable synthetic backend: never performs transfers or real external actions. */
import http from 'node:http';
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,lstatSync,chmodSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {digest} from './authority.js';
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
    this.lookup=this.db.prepare('SELECT request_hash,status FROM synthetic_actions WHERE operation_id=?');
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
  count(){return this.db.prepare('SELECT count(*) AS n FROM synthetic_actions').get().n;}
  close(){this.db.close();}
}
export function createDurableSyntheticBackend({secret,store}){
  if(typeof secret!=='string'||secret.length<32||!store||typeof store.apply!=='function')throw Error('Synthetic backend requires secret and durable store');
  return http.createServer(async(req,res)=>{
    if(req.url==='/healthz'&&req.method==='GET')return respond(res,200,{status:'ok'});
    if(req.url!=='/internal/execute'||req.method!=='POST')return respond(res,404,{error:'not-found'});
    if(req.headers.authorization!==`Bearer ${secret}`)return respond(res,401,{error:'unauthorized'});
    try{const body=await readJson(req);const result=store.apply(body);return respond(res,result.http,result);}
    catch{return respond(res,400,{error:'invalid-request'});}
  });
}
