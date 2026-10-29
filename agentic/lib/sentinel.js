/** Local single-node sentinel. Event hash chain detects naive editing, NOT privileged truncation or re-hashing. */
import {DatabaseSync} from 'node:sqlite';
import {createHash,randomBytes} from 'node:crypto';
import {mkdirSync,lstatSync,chmodSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {AuthorityError,canonical} from './authority.js';
const sha=x=>createHash('sha256').update(x).digest('hex');
export class LocalSentinel{
 constructor(path,{threshold=5,windowMs=60000,cooldownMs=300000,now=()=>Date.now()}={}){
  if(!Number.isSafeInteger(threshold)||threshold<2||threshold>100||![windowMs,cooldownMs].every(x=>Number.isSafeInteger(x)&&x>0)||typeof now!=='function')throw Error('invalid-sentinel-config');
  mkdirSync(dirname(resolve(path)),{recursive:true,mode:0o700});
  try{const stat=lstatSync(path);if(!stat.isFile()||stat.isSymbolicLink())throw Error('unsafe-sentinel-db');}catch(e){if(e.code!=='ENOENT')throw e;}
  this.db=new DatabaseSync(path);this.now=now;this.threshold=threshold;this.windowMs=windowMs;this.cooldownMs=cooldownMs;
   this.db.exec("PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS config(id INTEGER PRIMARY KEY CHECK(id=1),stop INTEGER NOT NULL,salt TEXT NOT NULL); CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,time_ms INTEGER NOT NULL,kind TEXT NOT NULL,source TEXT NOT NULL,reason TEXT NOT NULL,previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL); CREATE TABLE IF NOT EXISTS quarantines(source TEXT PRIMARY KEY,until_ms INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS alert_outbox(event_seq INTEGER PRIMARY KEY,delivered_at INTEGER);");
  this.db.prepare('INSERT OR IGNORE INTO config (id,stop,salt) VALUES (1,0,?)').run(randomBytes(32).toString('hex'));
  if(process.platform!=='win32')chmodSync(path,0o600);
 }
 sourceKey(remote){return sha(this.db.prepare('SELECT salt FROM config WHERE id=1').get().salt+'|'+String(remote??'unknown').slice(0,180));}
 isStopped(){return this.db.prepare('SELECT stop FROM config WHERE id=1').get().stop===1;}
 stop(enabled){
  if(typeof enabled!=='boolean')throw new AuthorityError('invalid-emergency-stop');
  try{
   this.db.exec('BEGIN IMMEDIATE');
   this.db.prepare('UPDATE config SET stop=? WHERE id=1').run(enabled?1:0);
  this.#append('control','local-operator',enabled?'emergency-stop-on':'emergency-stop-off');
   this.db.exec('COMMIT');
  }catch{try{this.db.exec('ROLLBACK');}catch{}throw new AuthorityError('sentinel-storage-unavailable');}
 }
 recover({expectedHead,operator,reason}={}){
  if(typeof expectedHead!=='string'||!/^[a-f0-9]{64}$/.test(expectedHead)||typeof operator!=='string'||!/^[\x21-\x7e]{1,120}$/.test(operator)||typeof reason!=='string'||!/^[\x20-\x7e]{1,140}$/.test(reason)||!reason.trim())throw new AuthorityError('invalid-recovery-request');
  try{
   this.db.exec('BEGIN IMMEDIATE');
   const chain=this.verifyChain();
   if(!chain.verified||chain.head!==expectedHead)throw new AuthorityError('sentinel-evidence-changed');
   if(!this.isStopped())throw new AuthorityError('sentinel-not-stopped');
   this.db.prepare('UPDATE config SET stop=0 WHERE id=1').run();
   this.#append('control',operator,'recovery:'+reason);
   this.db.exec('COMMIT');
  }catch(error){try{this.db.exec('ROLLBACK');}catch{}if(error instanceof AuthorityError)throw error;throw new AuthorityError('sentinel-storage-unavailable');}
 }
 #time(){
  const time=this.now(),last=this.db.prepare('SELECT time_ms FROM events ORDER BY seq DESC LIMIT 1').get();
  if(!Number.isSafeInteger(time)||time<0||last&&time<last.time_ms)throw new AuthorityError('invalid-sentinel-clock');
  return time;
 }
 isBlocked(remote){if(this.isStopped())return true;const time=this.#time(),q=this.db.prepare('SELECT until_ms FROM quarantines WHERE source=?').get(this.sourceKey(remote));return Boolean(q&&q.until_ms>time);}
 record(kind,remote,reason){
  if(!['deny','allow','control','quarantine'].includes(kind)||typeof reason!=='string'||!reason||reason.length>160)throw new AuthorityError('invalid-sentinel-event');
  try{
   this.db.exec('BEGIN IMMEDIATE');
    this.#append(kind,remote,reason);
   this.db.exec('COMMIT');return {recorded:true};
  }catch{try{this.db.exec('ROLLBACK');}catch{}throw new AuthorityError('sentinel-storage-unavailable');}
 }
 #append(kind,remote,reason){
    const source=this.sourceKey(remote),time=this.#time();
    const previous=this.db.prepare('SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1').get()?.event_hash??'GENESIS';
    const payload={time_ms:time,kind,source,reason},hash=sha(previous+'\n'+canonical(payload).toString('utf8'));
   const inserted=this.db.prepare('INSERT INTO events(time_ms,kind,source,reason,previous_hash,event_hash) VALUES(?,?,?,?,?,?)').run(time,kind,source,reason,previous,hash);
   if(kind==='quarantine'||kind==='control')this.db.prepare('INSERT INTO alert_outbox(event_seq) VALUES(?)').run(inserted.lastInsertRowid);
    if(kind==='deny'){
     const n=this.db.prepare("SELECT COUNT(*) AS count FROM events WHERE kind='deny' AND source=? AND time_ms>=?").get(source,time-this.windowMs).count;
      if(n>=this.threshold){
      const current=this.db.prepare('SELECT until_ms FROM quarantines WHERE source=?').get(source),until=time+this.cooldownMs;
      if(!Number.isSafeInteger(until))throw new AuthorityError('invalid-sentinel-clock');
       if(!current||until>current.until_ms){
        this.db.prepare('INSERT INTO quarantines(source,until_ms) VALUES(?,?) ON CONFLICT(source) DO UPDATE SET until_ms=excluded.until_ms').run(source,until);
        this.#append('quarantine',remote,'denial-threshold');
       }
      }
    }
 }
 pendingAlerts(limit=100){
  if(!Number.isSafeInteger(limit)||limit<1||limit>100)throw new AuthorityError('invalid-alert-limit');
  return this.db.prepare('SELECT e.seq,e.time_ms,e.kind,e.source,e.reason,e.previous_hash,e.event_hash FROM alert_outbox a JOIN events e ON e.seq=a.event_seq WHERE a.delivered_at IS NULL ORDER BY e.seq LIMIT ?').all(limit).map(row=>({...row}));
 }
 async deliverAlerts({url,fetchFn=fetch,limit=100}={}){
  let endpoint;try{endpoint=new URL(url);}catch{throw new AuthorityError('invalid-alert-endpoint');}
  if(endpoint.protocol!=='https:'||endpoint.username||endpoint.password||endpoint.hash||typeof fetchFn!=='function')throw new AuthorityError('invalid-alert-endpoint');
  if(!this.verifyChain().verified)throw new AuthorityError('sentinel-evidence-changed');
   const alerts=this.pendingAlerts(limit);let attempted=0,delivered=0,failed=false;
  for(const alert of alerts){
    attempted++;
    let response;try{response=await fetchFn(endpoint,{method:'POST',redirect:'error',signal:AbortSignal.timeout(3000),headers:{'content-type':'application/json'},body:JSON.stringify({format:'faraday-sentinel-alert-v1',event:alert})});}catch{failed=true;break;}
    try{await response?.body?.cancel();}catch{}
    if(!response?.ok){failed=true;break;}
  const time=this.#time();
   try{this.db.prepare('UPDATE alert_outbox SET delivered_at=? WHERE event_seq=? AND delivered_at IS NULL').run(time,alert.seq);}catch{throw new AuthorityError('sentinel-storage-unavailable');}
   delivered++;
  }
   return {attempted,delivered,failed,pending:this.pendingAlerts(1).length>0};
 }
 verifyChain(){const rows=this.db.prepare('SELECT * FROM events ORDER BY seq').all();let previous='GENESIS';
  for(const e of rows){const payload={time_ms:e.time_ms,kind:e.kind,source:e.source,reason:e.reason};if(e.previous_hash!==previous||e.event_hash!==sha(previous+'\n'+canonical(payload).toString('utf8')))return {verified:false,count:rows.length,at:e.seq};previous=e.event_hash;}
  return {verified:true,count:rows.length,head:previous};
 }
 status(){return {stopped:this.isStopped(),events:this.db.prepare('SELECT COUNT(*) AS n FROM events').get().n,chain:this.verifyChain()};}
 close(){this.db.close();}
}
