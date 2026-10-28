/** Independent Ed25519 evidence from the synthetic backend, not the gateway.
 * Not a notarization of real-world effects and not a trusted hardware attestation.
 */
import {createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import {canonical,AuthorityError} from './authority.js';
const DOMAIN=Buffer.from('FARADAY-BACKEND-EVIDENCE-v1\0');
const fields=['version','operationId','requestHash','status','recordedAt'];
const encode=claims=>Buffer.concat([DOMAIN,canonical(claims)]);
function check(claims){
  if(!claims || typeof claims!=='object'||Array.isArray(claims)||Object.keys(claims).sort().join('|')!==fields.slice().sort().join('|')||claims.version!==1||claims.status!=='simulated'||typeof claims.operationId!=='string'||!/^[-_a-zA-Z0-9]{20,128}$/.test(claims.operationId)||typeof claims.requestHash!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(claims.requestHash)||!Number.isSafeInteger(claims.recordedAt)||claims.recordedAt<1)throw new AuthorityError('invalid-backend-attestation');
}
export function signBackendAttestation({privatePem,claims}){
  check(claims);return {claims,signature:sign(null,encode(claims),createPrivateKey(privatePem)).toString('base64url')};
}
export function verifyBackendAttestation({publicPem,attestation,operationId,requestHash}){
  if(!attestation||typeof attestation!=='object'||Array.isArray(attestation)||Object.keys(attestation).sort().join('|')!=='claims|signature')throw new AuthorityError('missing-backend-attestation');
  const {claims,signature}=attestation;check(claims);
  if(claims.operationId!==operationId||claims.requestHash!==requestHash||typeof signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signature))throw new AuthorityError('backend-attestation-mismatch');
  const signatureBytes=Buffer.from(signature,'base64url');if(signatureBytes.toString('base64url')!==signature)throw new AuthorityError('invalid-backend-signature');
  let ok=false;try{ok=verify(null,encode(claims),createPublicKey(publicPem),signatureBytes);}catch{throw new AuthorityError('invalid-backend-signature');}
  if(!ok)throw new AuthorityError('invalid-backend-signature');
  return {verified:true,operationId,requestHash};
}
