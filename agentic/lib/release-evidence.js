import {createHash,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {canonical} from './authority.js';

const DOMAIN=Buffer.from('FARADAY-RELEASE-EVIDENCE-V1\0');
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
function validBytes(artifact,sbom){
 if(!Buffer.isBuffer(artifact)||artifact.length<1||artifact.length>100*1024*1024||!Buffer.isBuffer(sbom)||sbom.length<1||sbom.length>10*1024*1024)throw Error('invalid-release-input');
}
function validClaims(claims){
 return exact(claims,['format','version','packageName','packageVersion','artifactSha256','sbomSha256'])&&claims.format==='faraday-release-evidence'&&claims.version===1&&
  typeof claims.packageName==='string'&&claims.packageName.length<=214&&/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/.test(claims.packageName)&&
  typeof claims.packageVersion==='string'&&claims.packageVersion.length<=100&&/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/.test(claims.packageVersion)&&
  /^[a-f0-9]{64}$/.test(claims.artifactSha256)&&/^[a-f0-9]{64}$/.test(claims.sbomSha256);
}
export function signReleaseEvidence({artifact,sbom,packageName,packageVersion,privatePem}={}){
 validBytes(artifact,sbom);
 const claims={format:'faraday-release-evidence',version:1,packageName,packageVersion,artifactSha256:sha256(artifact),sbomSha256:sha256(sbom)};
 if(!validClaims(claims))throw Error('invalid-release-claims');
 let key;try{key=createPrivateKey(privatePem);if(key.asymmetricKeyType!=='ed25519')throw Error();}catch{throw Error('invalid-release-key');}
 return {claims,signature:sign(null,Buffer.concat([DOMAIN,canonical(claims)]),key).toString('base64url')};
}
export function verifyReleaseEvidence({artifact,sbom,evidence,publicPem,expectedPackageName,expectedPackageVersion}={}){
 validBytes(artifact,sbom);
 if(!exact(evidence,['claims','signature'])||!validClaims(evidence.claims)||typeof evidence.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(evidence.signature)||Buffer.from(evidence.signature,'base64url').toString('base64url')!==evidence.signature)throw Error('invalid-release-evidence');
 if(typeof expectedPackageName!=='string'||typeof expectedPackageVersion!=='string'||evidence.claims.packageName!==expectedPackageName||evidence.claims.packageVersion!==expectedPackageVersion)throw Error('release-identity-mismatch');
 let valid=false;try{const key=createPublicKey(publicPem);valid=key.asymmetricKeyType==='ed25519'&&verify(null,Buffer.concat([DOMAIN,canonical(evidence.claims)]),key,Buffer.from(evidence.signature,'base64url'));}catch{}
 if(!valid)throw Error('invalid-release-signature');
 if(sha256(artifact)!==evidence.claims.artifactSha256||sha256(sbom)!==evidence.claims.sbomSha256)throw Error('release-hash-mismatch');
 return {verified:true,packageName:evidence.claims.packageName,packageVersion:evidence.claims.packageVersion,artifactSha256:evidence.claims.artifactSha256,sbomSha256:evidence.claims.sbomSha256};
}