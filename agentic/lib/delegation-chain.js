/** R14 preview — cryptographic, non-amplifying agent delegation.
 * The offline issuer-signed root is NOT human OIDC token exchange.
 * Must be combined with signed FARADAY execution proof and replay ledger.
 */
import {createPrivateKey,createPublicKey,sign,verify,randomBytes} from 'node:crypto';
import {canonical,digest} from './authority.js';
const DOMAIN=Buffer.from('FARADAY-R14-DELEGATION-V1\0');
const validId=s=>typeof s==='string'&&s.length>=3&&s.length<=160&&/^[A-Za-z0-9:._/-]+$/.test(s);
const validAgent=s=>validId(s)&&s.startsWith('faraday://');
const validNonce=s=>typeof s==='string'&&/^[A-Za-z0-9_-]{24,128}$/.test(s);
const keys=(o,expected)=>o&&typeof o==='object'&&!Array.isArray(o)&&
 Object.keys(o).sort().join('|')===[...expected].sort().join('|');
const reject=()=>{throw Error('delegation-denied');};
const input=payload=>Buffer.concat([DOMAIN,canonical(payload)]);
const nonce=()=>randomBytes(24).toString('base64url');
function signed(privatePem,payload){
 if(typeof privatePem!=='string')reject();
 return {payload,signature:sign(null,input(payload),createPrivateKey(privatePem)).toString('base64url')};
}
function checkSignature(publicPem,packet){
 if(!keys(packet,['payload','signature'])||typeof publicPem!=='string'||
  typeof packet.signature!=='string'||!/^[A-Za-z0-9_-]{80,128}$/.test(packet.signature))reject();
 let valid=false;
 try{const raw=Buffer.from(packet.signature,'base64url');
  if(raw.toString('base64url')!==packet.signature)reject();
  valid=verify(null,input(packet.payload),createPublicKey(publicPem),raw);}
 catch{reject();}
 if(!valid)reject();return packet.payload;
}
function checkScope(s){
 if(!keys(s,['tool','resource','action','maxAmountCents'])||
  !validId(s.tool)||!validId(s.resource)||!validId(s.action)||
  !Number.isSafeInteger(s.maxAmountCents)||s.maxAmountCents<1||s.maxAmountCents>20000)reject();
}
function checkTime(p,now,parentExpiry=null){
 if(!Number.isSafeInteger(now)||!Number.isSafeInteger(p.iat)||!Number.isSafeInteger(p.exp)||
  p.iat>now+2||p.exp<=now||p.exp<=p.iat||p.exp-p.iat>900||
  parentExpiry!==null&&p.exp>parentExpiry)reject();
}
export function issueDelegationRoot({issuerPrivatePem,subject,agent,scope,now=Math.floor(Date.now()/1000),ttl=120}){
 if(!validId(subject)||!validAgent(agent)||!Number.isSafeInteger(ttl)||ttl<1||ttl>900)reject();
 checkScope(scope);
 return signed(issuerPrivatePem,{v:1,kind:'root',subject,agent,scope,iat:now,exp:now+ttl,nonce:nonce()});
}
export function delegateNarrower({fromPrivatePem,fromAgent,toAgent,parent,maxAmountCents,
 now=Math.floor(Date.now()/1000),ttl=60}){
 if(!validAgent(fromAgent)||!validAgent(toAgent)||fromAgent===toAgent||
  !Number.isSafeInteger(ttl)||ttl<1||ttl>900||
  !Number.isSafeInteger(maxAmountCents)||maxAmountCents<1)reject();
 const prev=parent?.payload;
 if(!prev||!Number.isSafeInteger(prev.exp)||!Number.isSafeInteger(prev.scope?.maxAmountCents)&&
  !Number.isSafeInteger(prev.maxAmountCents))reject();
 const priorLimit=prev.kind==='root'?prev.scope?.maxAmountCents:prev.maxAmountCents;
 const priorAgent=prev.kind==='root'?prev.agent:prev.to;
 if(fromAgent!==priorAgent||maxAmountCents>priorLimit||now+ttl>prev.exp)reject();
 return signed(fromPrivatePem,{v:1,kind:'hop',from:fromAgent,to:toAgent,
  parentHash:digest(parent),maxAmountCents,iat:now,exp:now+ttl,nonce:nonce()});
}
/** The trusted caller supplies registry + independently maintained revocations.
 * It must check the final agent against a separate FARADAY execution proof.
 */
export function verifyDelegationChain({chain,issuerPublicPem,agentPublicKeys,revoked,expected,
 now=Math.floor(Date.now()/1000)}={}){
 if(!Array.isArray(chain)||chain.length<1||chain.length>4||
  typeof revoked!=='function'||!agentPublicKeys||typeof agentPublicKeys!=='object'||
  !expected||typeof expected!=='object')reject();
 const root=checkSignature(issuerPublicPem,chain[0]);
 if(!keys(root,['v','kind','subject','agent','scope','iat','exp','nonce'])||
  root.v!==1||root.kind!=='root'||!validId(root.subject)||!validAgent(root.agent)||!validNonce(root.nonce))reject();
 checkTime(root,now);checkScope(root.scope);
 if(revoked('subject',root.subject)!==false||revoked('nonce',root.nonce)!==false)reject();
 const used=new Set([root.agent]),nonces=new Set([root.nonce]);
 let last=root.agent,max=root.scope.maxAmountCents,exp=root.exp;
 for(let i=1;i<chain.length;i++){
  const p=checkSignature(agentPublicKeys[last],chain[i]);
  if(!keys(p,['v','kind','from','to','parentHash','maxAmountCents','iat','exp','nonce'])||
   p.v!==1||p.kind!=='hop'||p.from!==last||!validAgent(p.to)||used.has(p.to)||
   p.parentHash!==digest(chain[i-1])||!validNonce(p.nonce)||nonces.has(p.nonce)||
   !Number.isSafeInteger(p.maxAmountCents)||p.maxAmountCents<1||p.maxAmountCents>max)reject();
  checkTime(p,now,exp);
  if(revoked('agent',p.to)!==false||revoked('nonce',p.nonce)!==false)reject();
  used.add(p.to);nonces.add(p.nonce);last=p.to;max=p.maxAmountCents;exp=p.exp;
 }
 if(expected.agent!==last||expected.tool!==root.scope.tool||
  expected.resource!==root.scope.resource||expected.action!==root.scope.action||
  !Number.isSafeInteger(expected.amountCents)||expected.amountCents<1||
  expected.amountCents>max||revoked('agent',last)!==false)reject();
 return Object.freeze({subject:root.subject,agent:last,maxAmountCents:max,
  expiresAt:exp,chainHash:digest(chain)});
}
