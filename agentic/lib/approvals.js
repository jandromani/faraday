/** FARADAY pilot: offline Ed25519 approvals; no private approver key in gateway. */
import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {AuthorityError,canonical,digest} from './authority.js';
const PREFIX=Buffer.from('FARADAY-APPROVAL-0.96\0');
const validText=s=>typeof s==='string'&&s.length>0&&s.length<=160;
const envelope=body=>Buffer.concat([PREFIX,canonical(body)]);
const expected=['version','approver','agent','tool','resource','action','capabilityHash','argsHash','issuedAt','expiresAt','decision'];
const exactKeys=(obj,keys)=>obj&&typeof obj==='object'&&!Array.isArray(obj)&&
 Object.keys(obj).length===keys.length&&keys.every(key=>Object.hasOwn(obj,key));
export function signApproval({approver,privatePem,capability,agent,tool,resource,action,args,now=Math.floor(Date.now()/1000),ttl=90,decision='approve'}){
 if(![approver,agent,tool,resource,action].every(validText)||typeof capability!=='string'||capability.length<20||!Number.isSafeInteger(now)||!Number.isSafeInteger(ttl)||ttl<1||ttl>300||!Number.isSafeInteger(now+ttl)||decision!=='approve')throw new AuthorityError('invalid-approval-request');
 const claims={version:1,approver,agent,tool,resource,action,capabilityHash:digest(capability),argsHash:digest(args),issuedAt:now,expiresAt:now+ttl,decision};
 return {claims,signature:sign(null,envelope(claims),createPrivateKey(privatePem)).toString('base64url')};
}
export function verifyApprovals({bundle,approverKeys,capability,agent,tool,resource,action,args,now=Math.floor(Date.now()/1000),quorum=2,requiredRoles=[],excludedPublicPem=null}){
 if(!Array.isArray(bundle)||!Number.isSafeInteger(now)||!Number.isSafeInteger(quorum)||quorum<1||quorum>12||bundle.length<quorum||bundle.length>12||!approverKeys||typeof approverKeys!=='object'||!Array.isArray(requiredRoles))throw new AuthorityError('approvals-required');
 const seen=new Set(),seenKeys=new Set(),roles=new Set();
 let excludedKey=null;
 if(excludedPublicPem!==null){try{const key=createPublicKey(excludedPublicPem);if(key.asymmetricKeyType!=='ed25519')throw Error('invalid key');excludedKey=createHash('sha256').update(key.export({format:'der',type:'spki'})).digest('hex');}catch{throw new AuthorityError('invalid-excluded-approval-key');}}
 for(const approval of bundle){
  if(!exactKeys(approval,['claims','signature'])||!exactKeys(approval.claims,expected))throw new AuthorityError('invalid-approval');
  const c=approval.claims;
  if(c.version!==1||c.decision!=='approve'||![c.approver,c.agent,c.tool,c.resource,c.action].every(validText)||c.capabilityHash!==digest(capability)||c.argsHash!==digest(args)||c.agent!==agent||c.tool!==tool||c.resource!==resource||c.action!==action||!Number.isSafeInteger(c.issuedAt)||!Number.isSafeInteger(c.expiresAt)||c.issuedAt>now+2||c.expiresAt<=now||c.expiresAt<=c.issuedAt||c.expiresAt-c.issuedAt>300||seen.has(c.approver)||!Object.hasOwn(approverKeys,c.approver))throw new AuthorityError('approval-mismatch-or-expired');
  const identity=approverKeys[c.approver],pub=typeof identity==='string'?identity:identity?.publicPem;
  if(!pub||typeof approval.signature!=='string'||!/^[A-Za-z0-9_-]{80,120}$/.test(approval.signature))throw new AuthorityError('invalid-approval-signature');
  const bytes=Buffer.from(approval.signature,'base64url');
  if(bytes.toString('base64url')!==approval.signature)throw new AuthorityError('noncanonical-approval-signature');
    let ok=false,key,keyFingerprint;try{
     key=createPublicKey(pub);
     if(key.asymmetricKeyType!=='ed25519')throw Error('invalid key type');
     keyFingerprint=createHash('sha256').update(key.export({format:'der',type:'spki'})).digest('hex');
     ok=verify(null,envelope(c),key,bytes);
    }catch{}
  if(!ok)throw new AuthorityError('invalid-approval-signature');
    if(keyFingerprint===excludedKey)throw new AuthorityError('approver-key-matches-agent');
    if(seenKeys.has(keyFingerprint))throw new AuthorityError('duplicate-approver-key');
    seenKeys.add(keyFingerprint);
  seen.add(c.approver);
  const role=typeof identity==='string'?undefined:identity?.role;if(role)roles.add(role);
 }
 if(seen.size<quorum||requiredRoles.some(role=>!roles.has(role)))throw new AuthorityError('approval-quorum-not-met');
 return {approved:true,count:seen.size,approvers:[...seen].sort(),approvalDigest:digest(bundle.map(x=>x.claims).sort((a,b)=>a.approver.localeCompare(b.approver)))};
}
export function encodeApprovals(bundle){return Buffer.from(canonical(bundle)).toString('base64url');}
export function decodeApprovals(header){
 if(typeof header!=='string'||header.length>10000||!/^[A-Za-z0-9_-]+$/.test(header))throw new AuthorityError('invalid-approval-bundle');
 const bytes=Buffer.from(header,'base64url');if(bytes.toString('base64url')!==header||bytes.length>7500)throw new AuthorityError('invalid-approval-bundle');
 try{return JSON.parse(bytes.toString('utf8'));}catch{throw new AuthorityError('invalid-approval-bundle');}
}
