/** Local single-node sentinel. Event hash chain detects naive editing, NOT privileged truncation or re-hashing. */
import {DatabaseSync} from 'node:sqlite';
import {createHash,randomBytes} from 'node:crypto';
import {mkdirSync,lstatSync,chmodSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {AuthorityError,canonical} from './authority.js';
const sha=x=>createHash('sha256').update(x).digest('hex');
export class LocalSentinel{
 constructor(path,{threshold=5,windowMs=60000,cooldownMs=300000,now=()=>Date.now()}={}){
  if(!Number.isSafeInteger(threshold)||threshold<2||threshold>100||![windowMs,cooldownMs].every(x=>Number.isSafeInteger(x)&&x>0))throw Error('invalid-sentinel-config');
  mkdirSync(dirname(resolve(path)),{recursive:true,mode:0o700});
  try{const stat=lstatSync(path);if(!stat.isFile()||stat.isSymbolicLink())throw Error('unsafe-sentinel-db');}catch(e){if(e.code!=='ENOENT')throw e;}
  this.db=new DatabaseSync(path);this.now=now;this.threshold=threshold;this.windowMs=windowMs;this.cooldownMs=cooldownMs;
  this.db.exec("PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS config(id INTEGER PRIMARY KEY CHECK(id=1),stop INTEGER NOT NULL,salt TEXT NOT NULL); CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,time_ms INTEGER NOT NULL,kind TEXT NOT NULL,source TEXT NOT NULL,reason TEXT NOT NULL,previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL); CREATE TABLE IF NOT EXISTS quarantines(source TEXT PRIMARY KEY,until_ms INTEGER NOT NULL);");
  this.db.prepare('INSERT OR IGNORE INTO config (id,stop,salt) VALUES (1,0,?)').run(randomBytes(32).toString('hex'));
  if(process.platform!=='win32')chmodSync(path,0o600);
 }
 sourceKey(remote){return sha(this.db.prepare('SELECT salt FROM config WHERE id=1').get().salt+'|'+String(remote??'unknown').slice(0,180));}
 isStopped(){return this.db.prepare('SELECT stop FROM config WHERE id=1').get().stop===1;}
 stop(enabled){if(typeof enabled!=='boolean')throw new AuthorityError('invalid-emergency-stop');this.db.prepare('UPDATE config SET stop=? WHERE id=1').run(enabled?1:0);this.record('control','local-operator',enabled?'emergency-stop-on':'emergency-stop-off');}
 isBlocked(remote){if(this.isStopped())return true;const q=this.db.prepare('SELECT until_ms FROM quarantines WHERE source=?').get(this.sourceKey(remote));return Boolean(q&&q.until_ms>this.now());}
 record(kind,remote,reason){
  if(!['deny','allow','control','quarantine'].includes(kind)||typeof reason!=='string'||!reason||reason.length>160)throw new AuthorityError('invalid-sentinel-event');
  const source=this.sourceKey(remote),time=this.now();
  try{
   this.db.exec('BEGIN IMMEDIATE');
   const previous=this.db.prepare('SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1').get()?.event_hash??'GENESIS';
   const payload={time_ms:time,kind,source,reason},hash=sha(previous+'\n'+canonical(payload).toString('utf8'));
   this.db.prepare('INSERT INTO events(time_ms,kind,source,reason,previous_hash,event_hash) VALUES(?,?,?,?,?,?)').run(time,kind,source,reason,previous,hash);
   if(kind==='deny'){
    const n=this.db.prepare("SELECT COUNT(*) AS count FROM events WHERE kind='deny' AND source=? AND time_ms>=?").get(source,time-this.windowMs).count;
    if(n>=this.threshold)this.db.prepare('INSERT INTO quarantines(source,until_ms) VALUES(?,?) ON CONFLICT(source) DO UPDATE SET until_ms=max(until_ms,excluded.until_ms)').run(source,time+this.cooldownMs);
   }
   this.db.exec('COMMIT');return {recorded:true};
  }catch{try{this.db.exec('ROLLBACK');}catch{}throw new AuthorityError('sentinel-storage-unavailable');}
 }
 verifyChain(){const rows=this.db.prepare('SELECT * FROM events ORDER BY seq').all();let previous='GENESIS';
  for(const e of rows){const payload={time_ms:e.time_ms,kind:e.kind,source:e.source,reason:e.reason};if(e.previous_hash!==previous||e.event_hash!==sha(previous+'\n'+canonical(payload).toString('utf8')))return {verified:false,count:rows.length,at:e.seq};previous=e.event_hash;}
  return {verified:true,count:rows.length,head:previous};
 }
 status(){return {stopped:this.isStopped(),events:this.db.prepare('SELECT COUNT(*) AS n FROM events').get().n,chain:this.verifyChain()};}
 close(){this.db.close();}
}
