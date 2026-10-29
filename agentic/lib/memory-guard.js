import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {chmodSync,lstatSync,mkdirSync,readFileSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {canonical} from './authority.js';

const DOMAIN=Buffer.from('FARADAY-MEMORY-DOCUMENT-V1\0');
const exact=(value,keys)=>value!==null&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const name=value=>typeof value==='string'&&/^[A-Za-z0-9._:-]{1,128}$/.test(value);
function validDocument(document){
 if(!exact(document,['version','id','source','issuedAt','expiresAt','text','facts'])||document.version!==1||!name(document.id)||!name(document.source)||
    !Number.isSafeInteger(document.issuedAt)||document.issuedAt<0||!Number.isSafeInteger(document.expiresAt)||document.expiresAt<=document.issuedAt||
    typeof document.text!=='string'||Buffer.byteLength(document.text)>4096||!Array.isArray(document.facts)||document.facts.length>32)return false;
 const seen=new Set();
 for(const fact of document.facts){
  if(!exact(fact,['key','value'])||!name(fact.key)||typeof fact.value!=='string'||!fact.value||Buffer.byteLength(fact.value)>128||seen.has(fact.key))return false;
  seen.add(fact.key);
 }
 return true;
}
function envelope(document){return Buffer.concat([DOMAIN,canonical(document)]);}
export function signMemoryDocument({document,privatePem}={}){
 if(!validDocument(document))throw Error('invalid-memory-document');
 const key=createPrivateKey(privatePem);if(key.asymmetricKeyType!=='ed25519')throw Error('invalid-memory-key');
 return {document,signature:sign(null,envelope(document),key).toString('base64url')};
}
export function verifyMemoryDocument({packet,trustedSources,now=Date.now()}={}){
 if(!Number.isSafeInteger(now)||now<0)throw Error('invalid-memory-clock');
 if(!exact(packet,['document','signature'])||!validDocument(packet.document))return {verified:false,reason:'invalid-document'};
 const {document,signature}=packet;
 if(!trustedSources||typeof trustedSources!=='object'||!Object.hasOwn(trustedSources,document.source))return {verified:false,reason:'unknown-source'};
 if(typeof signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signature)||Buffer.from(signature,'base64url').toString('base64url')!==signature)return {verified:false,reason:'invalid-signature'};
 let valid=false;try{const key=createPublicKey(trustedSources[document.source]);valid=key.asymmetricKeyType==='ed25519'&&verify(null,envelope(document),key,Buffer.from(signature,'base64url'));}catch{}
 if(!valid)return {verified:false,reason:'invalid-signature'};
 if(document.issuedAt>now||document.expiresAt<=now)return {verified:false,reason:'not-current'};
 return {verified:true,source:document.source,id:document.id};
}
const hash=serialized=>createHash('sha256').update(serialized).digest('hex');
export class LocalMemoryGuard{
 constructor(path,{trustedSources={},now=()=>Date.now()}={}){
  if(!trustedSources||typeof trustedSources!=='object'||Array.isArray(trustedSources)||typeof now!=='function'||Object.entries(trustedSources).some(([source,key])=>!name(source)||typeof key!=='string'))throw Error('invalid-memory-config');
  mkdirSync(dirname(resolve(path)),{recursive:true,mode:0o700});
  try{const stat=lstatSync(path);if(!stat.isFile()||stat.isSymbolicLink())throw Error('unsafe-memory-db');}catch(error){if(error.code!=='ENOENT')throw error;}
  this.db=new DatabaseSync(path);this.trustedSources={...trustedSources};this.now=now;
   this.db.exec("PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS memory_documents (digest TEXT PRIMARY KEY, packet_json TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('quarantined','approved')), reason TEXT NOT NULL); CREATE TABLE IF NOT EXISTS memory_reviews (digest TEXT PRIMARY KEY, reviewer TEXT NOT NULL, reviewed_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS memory_clock (id INTEGER PRIMARY KEY CHECK(id=1), last_seen_ms INTEGER NOT NULL);");
  if(process.platform!=='win32')chmodSync(path,0o600);
 }
 #check(row,now){
  if(hash(row.packet_json)!==row.digest)throw Error('memory-storage-corruption');
  let packet;try{packet=JSON.parse(row.packet_json);}catch{throw Error('memory-storage-corruption');}
  return {packet,verification:verifyMemoryDocument({packet,trustedSources:this.trustedSources,now})};
 }
 #time(){
  const now=this.now();if(!Number.isSafeInteger(now)||now<0)throw Error('invalid-memory-clock');
  const previous=this.db.prepare('SELECT last_seen_ms FROM memory_clock WHERE id=1').get();
  if(previous&&now<previous.last_seen_ms)throw Error('memory-clock-rollback');
  this.db.prepare('INSERT INTO memory_clock(id,last_seen_ms) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET last_seen_ms=excluded.last_seen_ms').run(now);
  return now;
 }
 #approvedRows(){
  const rows=this.db.prepare("SELECT d.*,r.digest AS review_digest FROM memory_documents d LEFT JOIN memory_reviews r ON r.digest=d.digest WHERE d.state='approved' ORDER BY d.digest LIMIT 1001").all();
  if(rows.length>1000)throw Error('memory-approved-limit');
  if(rows.some(row=>row.review_digest===null))throw Error('memory-review-missing');
  return rows;
 }
 ingest(packet){
  let serialized;try{serialized=JSON.stringify(packet);}catch{throw Error('invalid-memory-packet');}
  if(typeof serialized!=='string'||Buffer.byteLength(serialized)>16384)throw Error('invalid-memory-packet');
   const digest=hash(serialized),snapshot=JSON.parse(serialized);
   try{
    this.db.exec('BEGIN IMMEDIATE');
    const verification=verifyMemoryDocument({packet:snapshot,trustedSources:this.trustedSources,now:this.#time()}),reason=verification.verified?'awaiting-review':verification.reason;
    this.db.prepare("INSERT OR IGNORE INTO memory_documents(digest,packet_json,state,reason) VALUES (?,?,'quarantined',?)").run(digest,serialized,reason);
    const state=this.db.prepare('SELECT state,reason FROM memory_documents WHERE digest=?').get(digest);
    this.db.exec('COMMIT');return {digest,...state};
   }catch(error){try{this.db.exec('ROLLBACK');}catch{}throw error;}
 }
 approve(digest,{reviewer}={}){
  if(typeof digest!=='string'||!/^[a-f0-9]{64}$/.test(digest)||!name(reviewer))throw Error('invalid-memory-review');
  try{
   this.db.exec('BEGIN IMMEDIATE');
   const row=this.db.prepare('SELECT * FROM memory_documents WHERE digest=?').get(digest);if(!row||row.state!=='quarantined')throw Error('memory-not-quarantined');
   const now=this.#time(),candidate=this.#check(row,now);if(!candidate.verification.verified)throw Error('memory-provenance-unverified');
  const existing=this.#approvedRows();if(existing.length>=1000)throw Error('memory-approved-limit');
   const facts=new Map(candidate.packet.document.facts.map(fact=>[fact.key,fact.value]));
   for(const item of existing){
    const previous=this.#check(item,now);
    if(!previous.verification.verified){if(previous.verification.reason==='not-current')continue;throw Error('memory-approved-evidence-invalid');}
    if(previous.packet.document.source===candidate.packet.document.source&&previous.packet.document.id===candidate.packet.document.id)throw Error('memory-duplicate-document-id');
    if(previous.packet.document.facts.some(fact=>facts.has(fact.key)&&facts.get(fact.key)!==fact.value))throw Error('memory-fact-conflict');
   }
   this.db.prepare("UPDATE memory_documents SET state='approved',reason='reviewed' WHERE digest=?").run(digest);
   this.db.prepare('INSERT INTO memory_reviews(digest,reviewer,reviewed_at) VALUES(?,?,?)').run(digest,reviewer,now);
   this.db.exec('COMMIT');return {digest,state:'approved'};
  }catch(error){try{this.db.exec('ROLLBACK');}catch{}throw error;}
 }
 quarantined({limit=100}={}){
  if(!Number.isSafeInteger(limit)||limit<1||limit>100)throw Error('invalid-memory-limit');
  return this.db.prepare("SELECT digest,state,reason FROM memory_documents WHERE state='quarantined' ORDER BY digest LIMIT ?").all(limit).map(row=>({...row}));
 }
 inspect(digest){
  if(typeof digest!=='string'||!/^[a-f0-9]{64}$/.test(digest))throw Error('invalid-memory-digest');
  try{
   this.db.exec('BEGIN IMMEDIATE');
   const now=this.#time(),row=this.db.prepare('SELECT * FROM memory_documents WHERE digest=?').get(digest);if(!row)throw Error('memory-not-found');
   const checked=this.#check(row,now);this.db.exec('COMMIT');
   return {digest,state:row.state,reason:row.reason,verification:checked.verification,packet:checked.packet};
  }catch(error){try{this.db.exec('ROLLBACK');}catch{}throw error;}
 }
 approved(){
   try{
    this.db.exec('BEGIN IMMEDIATE');
    const now=this.#time(),rows=this.#approvedRows(),documents=[],facts=new Map(),ids=new Set();
    for(const row of rows){
     const checked=this.#check(row,now);
     if(!checked.verification.verified){if(checked.verification.reason==='not-current')continue;throw Error('memory-approved-evidence-invalid');}
     const document=checked.packet.document,id=JSON.stringify([document.source,document.id]);
     if(ids.has(id))throw Error('memory-duplicate-document-id');ids.add(id);
     for(const fact of document.facts){if(facts.has(fact.key)&&facts.get(fact.key)!==fact.value)throw Error('memory-fact-conflict');facts.set(fact.key,fact.value);}
     documents.push(document);
    }
    this.db.exec('COMMIT');return documents;
   }catch(error){try{this.db.exec('ROLLBACK');}catch{}throw error;}
 }
 close(){this.db.close();}
}
export function readMemoryJson(path){
 const stat=lstatSync(path);if(!stat.isFile()||stat.isSymbolicLink()||stat.size>65536)throw Error('unsafe-memory-input');
 return JSON.parse(readFileSync(path,'utf8'));
}