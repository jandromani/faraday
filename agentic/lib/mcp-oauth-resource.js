/** MCP OAuth 2.x Resource Server boundary, pinned JWKS (no dynamic network fetch).
 * Verifies bearer access tokens; it DOES NOT act as an OAuth Authorization Server.
 * HTTPS / public validation and TLS termination are deployment responsibilities.
 */
import {createPublicKey,verify} from 'node:crypto';

export class OAuthBoundaryError extends Error {
  constructor(code,status=401){super(code);this.code=code;this.status=status;}
}
function reject(code,status=401){throw new OAuthBoundaryError(code,status);}
function strictB64(s,max=16384){
  if(typeof s!=='string'||s.length<1||s.length>max||!/^[A-Za-z0-9_-]+$/.test(s))reject('invalid_token');
  const decoded=Buffer.from(s,'base64url');if(decoded.toString('base64url')!==s)reject('invalid_token');return decoded;
}
function jsonPart(part){let data;try{data=JSON.parse(strictB64(part).toString('utf8'));}catch{reject('invalid_token');}
  if(!data||typeof data!=='object'||Array.isArray(data))reject('invalid_token');return data;
}
function validateHttps(url,name,{allowHttpLoopback=false}={}){
  let u;try{u=new URL(url);}catch{throw Error(`Invalid ${name}`);}
  if(u.hash||u.username||u.password||u.search||!u.hostname||
    !(u.protocol==='https:'||(allowHttpLoopback&&u.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(u.hostname))))throw Error(`Invalid ${name}`);
  return u.href.replace(/\/$/,'');
}
const scopes=(value)=>typeof value==='string'?value.split(' ').filter(Boolean):[];
/** Config: {issuer,resource,authorizationServers,publicJwks:[{kid,kty,crv,x,...}],requiredScopes,allowHttpLoopback:false}.
 * Private keys are rejected, so no long-lived signing secret is introduced into the gateway.
 */
export class PinnedOAuthResource {
  constructor({issuer,resource,authorizationServers=[issuer],publicJwks,readScope='mcp:tools:read',executeScope='mcp:tools:execute',allowHttpLoopback=false,clock=()=>Math.floor(Date.now()/1000),maxTokenAge=3600,revocations=null,tokenProfile='rfc9068',allowedClientIds=[]}){
    this.issuer=validateHttps(issuer,'issuer',{allowHttpLoopback});
    this.resource=validateHttps(resource,'resource',{allowHttpLoopback});
    if(!this.resource.endsWith('/mcp'))throw Error('OAuth resource URL must end in /mcp');
    if(!Array.isArray(authorizationServers)||authorizationServers.length<1||authorizationServers.length>8)throw Error('Invalid authorization server set');
    this.authorizationServers=authorizationServers.map(u=>validateHttps(u,'authorization server',{allowHttpLoopback}));
    if(!this.authorizationServers.includes(this.issuer))throw Error('Issuer not authorized for resource');
    if(!/^[\w:-]{3,100}$/.test(readScope)||!/^[\w:-]{3,100}$/.test(executeScope))throw Error('Invalid scopes');
    if(typeof clock!=='function'||!Number.isSafeInteger(maxTokenAge)||maxTokenAge<1)throw Error('Invalid token clock or maximum age');
    if(!['rfc9068','keycloak-oidc'].includes(tokenProfile))throw Error('Invalid OAuth token profile');
    if(tokenProfile==='keycloak-oidc'&&(!Array.isArray(allowedClientIds)||allowedClientIds.length<1||allowedClientIds.length>16||
      allowedClientIds.some(id=>typeof id!=='string'||!/^[A-Za-z0-9_.-]{3,128}$/.test(id))))throw Error('Keycloak client allowlist required');
    this.tokenProfile=tokenProfile;this.allowedClientIds=new Set(allowedClientIds);
    this.readScope=readScope;this.executeScope=executeScope;this.clock=clock;this.maxTokenAge=maxTokenAge;
    if(revocations!==null && typeof revocations.isRevoked!=='function')throw Error('invalid-revocation-backend');
    this.revocations=revocations;
    if(!Array.isArray(publicJwks)||publicJwks.length<1||publicJwks.length>20)throw Error('Pinned public JWKS required');
    this.replacePublicJwks(publicJwks);
    this.metadata=Object.freeze({resource:this.resource,authorization_servers:this.authorizationServers,scopes_supported:[readScope,executeScope],bearer_methods_supported:['header']});
  }
  /** Operator initiated atomic replacement: no JWKS fetching or untrusted automatic updates. */
  replacePublicJwks(publicJwks){
    if(!Array.isArray(publicJwks)||publicJwks.length<1||publicJwks.length>20)throw Error('Pinned public JWKS required');
    const newKeys=new Map();
    for(const jwk of publicJwks){
      if(!jwk||typeof jwk.kid!=='string'||!/^[A-Za-z0-9._-]{1,120}$/.test(jwk.kid)||newKeys.has(jwk.kid)||('d' in jwk)||('p' in jwk)||('q' in jwk))throw Error('Invalid or duplicate public JWK');
      if(jwk.kty!=='RSA'&&!(jwk.kty==='OKP'&&jwk.crv==='Ed25519'))throw Error('Unsupported JWK key type');
      const alg=jwk.kty==='RSA'?'RS256':'EdDSA';
      if(jwk.alg&&jwk.alg!==alg)throw Error('JWK algorithm mismatch');
      if(jwk.use&&jwk.use!=='sig')throw Error('JWK not for signature');
      try{
        const publicKey=createPublicKey({format:'jwk',key:jwk});
        if(jwk.kty==='RSA' && (publicKey.asymmetricKeyDetails?.modulusLength??0)<2048)throw Error('RSA key too short');
        newKeys.set(jwk.kid,{key:publicKey,alg});
      }catch{throw Error('Unusable or weak public JWK');}
    }
    this.keys=newKeys;
    return Object.freeze({kids:[...newKeys.keys()]});
  }
  challenge(scope=this.readScope,error=null){
    // Metadata URL is explicitly provisioned, not constructed from request Host.
    const u=new URL(this.resource);
    const metadata=`${u.origin}/.well-known/oauth-protected-resource${u.pathname}`;
    return `Bearer resource_metadata="${metadata}", scope="${scope}"${error?`, error="${error}"`:''}`;
  }
  verifyAuthorization(header,scope){
    if(typeof header!=='string'||!/^Bearer [A-Za-z0-9_.-]{1,24576}$/.test(header))reject('invalid_token');
    const raw=header.slice(7);if(raw.length>24576)reject('invalid_token');
    const parts=raw.split('.');if(parts.length!==3)reject('invalid_token');
    const [headPart,payloadPart,signaturePart]=parts;
    const head=jsonPart(headPart),payload=jsonPart(payloadPart);
    if(typeof head.kid!=='string'||!this.keys.has(head.kid)||!(head.typ==='at+jwt'||(this.tokenProfile==='keycloak-oidc'&&head.typ==='JWT'))||!['RS256','EdDSA'].includes(head.alg)||head.crit||head.jwk||head.jku||head.x5u)reject('invalid_token');
    const candidate=this.keys.get(head.kid);if(candidate.alg!==head.alg)reject('invalid_token');
    const signature=strictB64(signaturePart,2048);
    const signingInput=Buffer.from(`${headPart}.${payloadPart}`);
    const ok=verify(head.alg==='RS256'?'RSA-SHA256':null,signingInput,candidate.key,signature);
    if(!ok)reject('invalid_token');
    const now=this.clock();
    if(!Number.isSafeInteger(now)||!Number.isSafeInteger(payload.exp)||!Number.isSafeInteger(payload.iat)||
       payload.exp<=now||payload.iat>now+30||payload.iat>payload.exp||now-payload.iat>this.maxTokenAge||
       (payload.nbf!==undefined&&(!Number.isSafeInteger(payload.nbf)||payload.nbf>now+30)))reject('invalid_token');
    const audienceAllowed=payload.aud===this.resource||(Array.isArray(payload.aud)&&
      (this.tokenProfile==='keycloak-oidc'?payload.aud.includes(this.resource):payload.aud.length===1&&payload.aud[0]===this.resource));
    if(payload.iss!==this.issuer||!audienceAllowed)reject('invalid_token');
    const clientId=this.tokenProfile==='keycloak-oidc'?payload.azp:payload.client_id;
    if(typeof payload.sub!=='string'||!payload.sub||payload.sub.length>256||
      typeof clientId!=='string'||!clientId||clientId.length>512||
      (this.tokenProfile==='keycloak-oidc'&&!this.allowedClientIds.has(clientId)))reject('invalid_token');
    if(typeof payload.scope!=='string'||payload.scope.length>2048||!scopes(payload.scope).includes(scope))reject('insufficient_scope',403);
    if(this.revocations){
      if(typeof payload.jti!=='string'||!/^[A-Za-z0-9._:-]{8,128}$/.test(payload.jti))reject('invalid_token');
      // A missing/unreadable ledger is a denial, never an implicit allow.
      try{if(this.revocations.isRevoked({jti:payload.jti,subject:payload.sub,clientId}))reject('invalid_token');}
      catch{reject('invalid_token');}
    }
    return {subject:payload.sub,clientId,scope,expiresAt:payload.exp,issuedAt:payload.iat};
  }
}
