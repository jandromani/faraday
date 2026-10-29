/** FARADAY Authority Preview v0.9 — cryptographic authorization for synthetic actions.
 * Issuer private signing key NEVER belongs in the gateway process.
 * This is not workload attestation, OAuth/OIDC, SPIFFE-SVID, or production IAM.
 */
import {createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {lstatSync, readFileSync, mkdirSync, chmodSync} from 'node:fs';
import {dirname,resolve} from 'node:path';

const D='FARADAY-0.9:';
export const MAX_AUTH_BYTES=16*1024;
export class AuthorityError extends Error {
  constructor(code){ super(code); this.name='AuthorityError'; this.code=code; }
}
const fail=(name)=>{throw new AuthorityError(name);};
function checked(value,depth=0){
  if(depth>24)fail('nesting-limit');
  if(value===null || typeof value==='boolean' || typeof value==='string')return value;
  if(typeof value==='number'){if(!Number.isSafeInteger(value))fail('non-integer-number');return value;}
  if(Array.isArray(value)){if(value.length>1000)fail('array-limit');return value.map(x=>checked(x,depth+1));}
  if(typeof value==='object'){
    const keys=Object.keys(value).sort();if(keys.length>200)fail('object-limit');
    const out={};
    for(const k of keys){if(['__proto__','constructor','prototype'].includes(k))fail('reserved-property');out[k]=checked(value[k],depth+1);}return out;
  }
  fail('invalid-json-value');
}
export function canonical(value){
  const bytes=Buffer.from(JSON.stringify(checked(value)));
  if(bytes.length>MAX_AUTH_BYTES)fail('oversize');
  return bytes;
}
const b64=(bytes)=>Buffer.from(bytes).toString('base64url');
const unb64=(input)=>{
  if(typeof input!=='string' || !/^[A-Za-z0-9_-]+$/.test(input) || input.length>MAX_AUTH_BYTES*2)fail('invalid-encoding');
  const raw=Buffer.from(input,'base64url');if(raw.toString('base64url')!==input)fail('noncanonical-encoding');return raw;
};
const mac=(domain,obj)=>Buffer.concat([Buffer.from(D+domain+':'),canonical(obj)]);
export const digest=(input)=>b64(createHash('sha256').update(typeof input==='string'?input:canonical(input)).digest());
export function newIdentity(){
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  return {privatePem:privateKey.export({format:'pem',type:'pkcs8'}),publicPem:publicKey.export({format:'pem',type:'spki'})};
}
function signObject(key,domain,payload){return {payload,sig:b64(sign(null,mac(domain,payload),createPrivateKey(key)))};}
function verifyObject(pub,domain,packet){
  if(!packet || typeof packet!=='object' || Array.isArray(packet) || Object.keys(packet).sort().join(',')!=='payload,sig')fail('invalid-signed-object');
  let ok=false;
  try{ok=verify(null,mac(domain,packet.payload),createPublicKey(pub),unb64(packet.sig));}catch(e){if(e instanceof AuthorityError)throw e;fail('invalid-signature');}
  if(!ok)fail('invalid-signature');return packet.payload;
}
function assertFields(obj,keys){
  if(!obj||typeof obj!=='object'||Array.isArray(obj))fail('invalid-claims');
  const actual=Object.keys(obj).sort(),expected=keys.slice().sort();
  if(actual.length!==expected.length||actual.some((key,index)=>key!==expected[index]))fail('invalid-claims');
}
function validTime(iat,exp,now,max){if(!Number.isSafeInteger(now)||!Number.isSafeInteger(iat)||!Number.isSafeInteger(exp)||iat>now+2||exp<=now||exp-iat<1||exp-iat>max)fail('expired-or-invalid-time');}
function validNonce(n){if(typeof n!=='string'||n.length<20||n.length>128||!/^[A-Za-z0-9_-]+$/.test(n))fail('invalid-nonce');}
const clockNow=()=>Math.floor(Date.now()/1000);
export function createIntent({agent,tool,resource,action,args,agentPrivatePem,now=clockNow(),ttl=25}){
  if(!Number.isSafeInteger(ttl)||ttl<1||ttl>30)fail('invalid-ttl');
  return signObject(agentPrivatePem,'issue',{ver:1,purpose:'issue',agent,tool,resource,action,args,iat:now,exp:now+ttl,nonce:b64(randomBytes(24))});
}
export function createExecution({agent,tool,resource,action,args,capability,agentPrivatePem,now=clockNow(),ttl=25}){
  if(!Number.isSafeInteger(ttl)||ttl<1||ttl>30)fail('invalid-ttl');
  return signObject(agentPrivatePem,'execute',{ver:1,purpose:'execute',agent,tool,resource,action,args,capHash:digest(capability),iat:now,exp:now+ttl,nonce:b64(randomBytes(24))});
}
function ensureRegistry(registry,agent){if(typeof agent!=='string'||!Object.hasOwn(registry,agent))fail('unknown-agent');return registry[agent];}
function identityProof(proof,registry,purpose,now){
  const p=proof?.payload;assertFields(p,purpose==='issue'?['ver','purpose','agent','tool','resource','action','args','iat','exp','nonce']:['ver','purpose','agent','tool','resource','action','args','capHash','iat','exp','nonce']);
  if(p.ver!==1||p.purpose!==purpose)fail('wrong-proof-purpose');
  validTime(p.iat,p.exp,now,30);validNonce(p.nonce);
  if(typeof p.tool!=='string'||typeof p.resource!=='string'||typeof p.action!=='string')fail('invalid-scope');
  verifyObject(ensureRegistry(registry,p.agent),purpose,proof);
  return p;
}
/** Policies authorize exact tool + action + resource; numeric amounts are optional bounds. */
export function evaluatePolicy(policy,{agent,tool,resource,action,args}){
  if(!policy||policy.version!==1||policy.mode!=='enforce'||!Array.isArray(policy.rules)||policy.rules.length>1000)fail('invalid-policy');
  if(!args||typeof args!=='object'||Array.isArray(args))fail('invalid-arguments');
  const encoded=canonical(args);if(encoded.length>8192)fail('arguments-too-large');
  for(const r of policy.rules){
    if(!r||typeof r!=='object'||Array.isArray(r)||
       Object.keys(r).some(key=>!['id','agent','tool','resource','action','required','exactKeys','equal','maxAmountCents'].includes(key))||
       !['id','agent','tool','resource','action'].every(key=>typeof r[key]==='string'&&r[key].length>0&&r[key].length<=512)||
       !Array.isArray(r.required)||r.required.length>200||r.required.some(key=>typeof key!=='string'||!key)||
       new Set(r.required).size!==r.required.length||
       (Object.hasOwn(r,'exactKeys')&&typeof r.exactKeys!=='boolean')||
       (Object.hasOwn(r,'equal')&&(!r.equal||typeof r.equal!=='object'||Array.isArray(r.equal)))||
       (Object.hasOwn(r,'maxAmountCents')&&(!Number.isSafeInteger(r.maxAmountCents)||r.maxAmountCents<1)))fail('invalid-policy');
    if(Object.hasOwn(r,'equal'))canonical(r.equal);
  }
  for(const r of policy.rules){
    if(r.agent!==agent||r.tool!==tool||r.resource!==resource||r.action!==action)continue;
    if(r.required.some(k=>!Object.hasOwn(args,k)))continue;
    if(r.exactKeys===true && Object.keys(args).length!==r.required.length)continue;
    if(r.equal && Object.entries(r.equal).some(([k,v])=>JSON.stringify(args[k])!==JSON.stringify(v)))continue;
    if(r.maxAmountCents!==undefined && (!Number.isSafeInteger(args.amount_cents)||args.amount_cents<1||args.amount_cents>r.maxAmountCents))continue;
    return {allowed:true,rule:r.id};
  }
  return {allowed:false,rule:null};
}
export class NonceLedger {
  constructor(path){
    mkdirSync(dirname(resolve(path)),{recursive:true,mode:0o700});
    this.db=new DatabaseSync(path);this.db.exec('PRAGMA busy_timeout=3000; CREATE TABLE IF NOT EXISTS consumed (key TEXT PRIMARY KEY, expiration INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS revoked (kind TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(kind,value))');
    this.insert=this.db.prepare('INSERT INTO consumed (key,expiration) VALUES (?,?)');
    this.findRevocation=this.db.prepare('SELECT 1 FROM revoked WHERE kind=? AND value=?');
  }
  revoke(kind,value){
    if(!['agent','issuer','capability'].includes(kind)||typeof value!=='string'||!value||value.length>512)fail('invalid-revocation');
    try{this.db.prepare('INSERT OR IGNORE INTO revoked(kind,value) VALUES (?,?)').run(kind,value);}
    catch{fail('revocation-ledger-unavailable');}
  }
  spend(keys,expiration,{revocations=[]}={}){
    if(!Array.isArray(keys)||keys.length<1||keys.some(k=>typeof k!=='string'||k.length>300))fail('invalid-ledger-key');
    if(!Array.isArray(revocations)||revocations.some(item=>!item||!['agent','issuer','capability'].includes(item.kind)||
       typeof item.value!=='string'||!item.value||item.value.length>512))fail('invalid-revocation');
    try{
      this.db.exec('BEGIN IMMEDIATE');
      for(const item of revocations)if(this.findRevocation.get(item.kind,item.value))fail('authority-revoked');
      for(const key of keys)this.insert.run(key,expiration);
      this.db.exec('COMMIT');
    }catch(e){try{this.db.exec('ROLLBACK');}catch{};if(e instanceof AuthorityError)throw e;fail('capability-replayed-or-ledger-unavailable');}
  }
  close(){this.db.close();}
}
export class AuthorityIssuer{
  constructor({issuerPrivatePem,kid,registry,policy,ledger,now=clockNow}){
    if(typeof kid!=='string'||!kid||kid.length>128)fail('invalid-key-id');
    this.key=issuerPrivatePem;this.kid=kid;this.registry=registry;this.policy=policy;this.ledger=ledger;this.now=now;
  }
  issue(proof,{ttl=60}={}){
    if(!Number.isSafeInteger(ttl)||ttl<1||ttl>300)fail('invalid-ttl');
    const now=this.now(),p=identityProof(proof,this.registry,'issue',now);
    const decision=evaluatePolicy(this.policy,p);if(!decision.allowed)fail('policy-denied');
    this.ledger.spend(['intent:'+p.agent+':'+p.nonce],p.exp,{revocations:[{kind:'agent',value:p.agent},{kind:'issuer',value:this.kid}]});
    const claims={v:1,kid:this.kid,iss:'faraday-authority-v09',aud:'faraday-gateway-v09',sub:p.agent,agentKey:digest(this.registry[p.agent]),tool:p.tool,resource:p.resource,action:p.action,argsHash:digest(p.args),rule:decision.rule,iat:now,exp:now+ttl,jti:b64(randomBytes(24))};
    return b64(canonical(signObject(this.key,'capability',claims)));
  }
}
export class AuthorityGate {
  constructor({issuerKeys,registry,policy,ledger,now=clockNow}){
    this.keys=issuerKeys;this.registry=registry;this.policy=policy;this.ledger=ledger;this.now=now;
  }
  authorize({capability,proof}){
    if(typeof capability!=='string'||capability.length>MAX_AUTH_BYTES*2)fail('invalid-capability');
    let obj;try{obj=JSON.parse(unb64(capability).toString('utf8'));}catch(e){if(e instanceof AuthorityError)throw e;fail('invalid-capability');}
    const c=obj?.payload;
    assertFields(c,['v','kid','iss','aud','sub','agentKey','tool','resource','action','argsHash','rule','iat','exp','jti']);
    if(c.v!==1||c.iss!=='faraday-authority-v09'||c.aud!=='faraday-gateway-v09')fail('wrong-audience-or-issuer');
    if(!Object.hasOwn(this.keys,c.kid))fail('unknown-issuer');
    verifyObject(this.keys[c.kid],'capability',obj);
    const now=this.now();validTime(c.iat,c.exp,now,300);validNonce(c.jti);
    const p=identityProof(proof,this.registry,'execute',now);
    if(p.agent!==c.sub||p.tool!==c.tool||p.resource!==c.resource||p.action!==c.action||digest(p.args)!==c.argsHash||p.capHash!==digest(capability)||digest(this.registry[p.agent])!==c.agentKey)fail('scope-mismatch');
    const decision=evaluatePolicy(this.policy,p);
    if(!decision.allowed||decision.rule!==c.rule)fail('policy-denied');
    this.ledger.spend(['cap:'+c.jti,'execute:'+p.agent+':'+p.nonce],c.exp,{revocations:[
      {kind:'agent',value:p.agent},{kind:'issuer',value:c.kid},{kind:'capability',value:c.jti}]});
    return {agent:p.agent,tool:p.tool,resource:p.resource,action:p.action,args:p.args,rule:decision.rule,jti:c.jti};
  }
}
/** Read a public or private PEM file from safe local storage. */
export function readKeyFile(path,{privateKey=false}={}){
  const stat=lstatSync(path);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.size>8192)fail('unsafe-key-file');
  if(privateKey&&process.platform!=='win32'&&(stat.mode&0o077)!==0)fail('unsafe-private-key-permissions');
  return readFileSync(path,'utf8');
}
