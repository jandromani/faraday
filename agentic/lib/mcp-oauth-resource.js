/** MCP OAuth resource boundary. Pinned public JWKS, no authorization server or network fetch. */
import {createPublicKey,verify} from 'node:crypto';
export class OAuthBoundaryError extends Error{
  constructor(code,status=401){super(code);this.code=code;this.status=status;}
}
const fail=(code,status=401)=>{throw new OAuthBoundaryError(code,status);};
function b64(s,max=16384){
  if(typeof s!=='string'||!s||s.length>max||!/^[A-Za-z0-9_-]+$/.test(s))fail('invalid_token');
  const b=Buffer.from(s,'base64url');if(b.toString('base64url')!==s)fail('invalid_token');return b;
}
function json(s){let obj;try{obj=JSON.parse(b64(s).toString('utf8'));}catch{fail('invalid_token');}
  if(!obj||typeof obj!=='object'||Array.isArray(obj))fail('invalid_token');return obj;
}
function url(v,label,allowLoopback){
  let x;try{x=new URL(v);}catch{throw Error('Invalid '+label);}
  if(x.username||x.password||x.search||x.hash||
     !(x.protocol==='https:'||(allowLoopback&&x.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(x.hostname))))throw Error('Invalid '+label);
  return x.href.replace(/\/$/,'');
}
export class PinnedOAuthResource{
  constructor({issuer,resource,authorizationServers=[issuer],publicJwks,readScope='mcp:tools:read',
    executeScope='mcp:tools:execute',allowHttpLoopback=false,clock=()=>Math.floor(Date.now()/1000),maxTokenAge=3600}){
    this.issuer=url(issuer,'issuer',allowHttpLoopback);
    this.resource=url(resource,'resource',allowHttpLoopback);
    if(!this.resource.endsWith('/mcp'))throw Error('Invalid MCP resource path');
    if(!Array.isArray(authorizationServers)||!authorizationServers.length||authorizationServers.length>8)throw Error('Invalid authorization servers');
    this.authorizationServers=authorizationServers.map(v=>url(v,'authorization server',allowHttpLoopback));
    if(!this.authorizationServers.includes(this.issuer))throw Error('Untrusted issuer');
    if(!/^[\w:-]{3,100}$/.test(readScope)||!/^[\w:-]{3,100}$/.test(executeScope))throw Error('Invalid scopes');
    this.readScope=readScope;this.executeScope=executeScope;this.clock=clock;this.maxTokenAge=maxTokenAge;
    if(!Array.isArray(publicJwks)||!publicJwks.length||publicJwks.length>20)throw Error('Pinned public JWKS required');
    this.keys=new Map();
    for(const jwk of publicJwks){
      if(!jwk||typeof jwk.kid!=='string'||!/^[A-Za-z0-9._-]{1,120}$/.test(jwk.kid)||
         this.keys.has(jwk.kid)||jwk.d||jwk.p||jwk.q||jwk.kty!=='RSA'&&!(jwk.kty==='OKP'&&jwk.crv==='Ed25519'))throw Error('Invalid or private JWK');
      const alg=jwk.kty==='RSA'?'RS256':'EdDSA';
      if(jwk.alg&&jwk.alg!==alg||jwk.use&&jwk.use!=='sig')throw Error('Invalid JWK algorithm');
      let key;try{key=createPublicKey({format:'jwk',key:jwk});}catch{throw Error('Unusable public JWK');}
      if(jwk.kty==='RSA'&&(key.asymmetricKeyDetails?.modulusLength??0)<2048)throw Error('Weak RSA key');
      this.keys.set(jwk.kid,{key,alg});
    }
    this.metadata=Object.freeze({resource:this.resource,authorization_servers:this.authorizationServers,
      scopes_supported:[readScope,executeScope],bearer_methods_supported:['header']});
  }
  challenge(scope=this.readScope,error=null){
    const u=new URL(this.resource);
    const endpoint=u.origin+'/.well-known/oauth-protected-resource'+u.pathname;
    return 'Bearer resource_metadata="'+endpoint+'", scope="'+scope+'"'+(error?', error="'+error+'"':'');
  }
  verifyAuthorization(header,scope){
    if(typeof header!=='string'||!/^Bearer [A-Za-z0-9_.-]{1,24576}$/.test(header))fail('invalid_token');
    const parts=header.slice(7).split('.');if(parts.length!==3)fail('invalid_token');
    const [h,p,s]=parts,hd=json(h),claims=json(p);
    if(hd.typ!=='at+jwt'||!this.keys.has(hd.kid)||hd.crit||hd.jwk||hd.jku||hd.x5u)fail('invalid_token');
    const key=this.keys.get(hd.kid);
    if(hd.alg!==key.alg)fail('invalid_token');
    let ok=false;try{ok=verify(key.alg==='RS256'?'RSA-SHA256':null,Buffer.from(h+'.'+p),key.key,b64(s,2048));}
    catch{fail('invalid_token');}
    if(!ok)fail('invalid_token');
    const now=this.clock();
    if(!Number.isSafeInteger(claims.iat)||!Number.isSafeInteger(claims.exp)||
       claims.exp<=now||claims.iat>now+30||claims.iat>claims.exp||now-claims.iat>this.maxTokenAge||
       claims.nbf!==undefined&&(!Number.isSafeInteger(claims.nbf)||claims.nbf>now+30))fail('invalid_token');
    if(claims.iss!==this.issuer||!(claims.aud===this.resource||
       Array.isArray(claims.aud)&&claims.aud.length===1&&claims.aud[0]===this.resource))fail('invalid_token');
    if(typeof claims.sub!=='string'||!claims.sub||claims.sub.length>256||
       typeof claims.client_id!=='string'||!claims.client_id||claims.client_id.length>512)fail('invalid_token');
    if(typeof claims.scope!=='string'||claims.scope.length>2048||!claims.scope.split(' ').includes(scope))fail('insufficient_scope',403);
    return {subject:claims.sub,clientId:claims.client_id,scope};
  }
}
