import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,readFileSync,symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync,sign} from 'node:crypto';
import {LocalOAuthRevocations} from '../lib/oauth-revocations.js';
import {PinnedOAuthResource} from '../lib/mcp-oauth-resource.js';
const now=1800000000,issuer='https://id.example',resource='https://mcp.example/mcp';
const key=()=>{const kp=generateKeyPairSync('ed25519');return {kp,jwk:{...kp.publicKey.export({format:'jwk'}),kid:'keyA',alg:'EdDSA',use:'sig'}}};
const signToken=(kp,{kid='keyA',jti='token-111',sub='faraday://lab/a',client_id='client-A',...extra}={})=>{
 const h=Buffer.from(JSON.stringify({typ:'at+jwt',alg:'EdDSA',kid})).toString('base64url');
 const p=Buffer.from(JSON.stringify({iss:issuer,aud:resource,sub,client_id,iat:now-10,exp:now+90,scope:'mcp:tools:read mcp:tools:execute',jti,...extra})).toString('base64url');
 return `Bearer ${h}.${p}.${sign(null,Buffer.from(`${h}.${p}`),kp.privateKey).toString('base64url')}`;
};
function fixture(t){const dir=mkdtempSync(join(tmpdir(),'faraday-revocation-test-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));const db=join(dir,'revocations.db');const writer=new LocalOAuthRevocations(db,{create:true});const reader=new LocalOAuthRevocations(db);t.after(()=>{reader.close();writer.close();});const k=key();const oauth=new PinnedOAuthResource({issuer,resource,publicJwks:[k.jwk],clock:()=>now,revocations:reader});return {db,writer,reader,k,oauth,dir};}
test('token revocation takes effect without process restart and survives new reader',t=>{
 const x=fixture(t),auth=signToken(x.k.kp);
 assert.equal(x.oauth.verifyAuthorization(auth,'mcp:tools:read').subject,'faraday://lab/a');
 x.writer.revoke('jti','token-111');
 assert.throws(()=>x.oauth.verifyAuthorization(auth,'mcp:tools:read'),/invalid_token/);
 const reopened=new LocalOAuthRevocations(x.db);assert.equal(reopened.isRevoked({jti:'token-111',subject:'a',clientId:'b'}),true);reopened.close();
 assert.equal(readFileSync(x.db).includes(Buffer.from('token-111')),false);
});
test('revoked agent blocks all new tokens; other agents continue',t=>{
 const x=fixture(t);
 x.writer.revoke('subject','faraday://lab/a');
 assert.throws(()=>x.oauth.verifyAuthorization(signToken(x.k.kp,{jti:'token-222'}),'mcp:tools:execute'),/invalid_token/);
 assert.equal(x.oauth.verifyAuthorization(signToken(x.k.kp,{jti:'token-333',sub:'faraday://lab/b'}),'mcp:tools:read').subject,'faraday://lab/b');
});
test('revoked client blocks other agents; separate client remains valid',t=>{
 const x=fixture(t);x.writer.revoke('client','client-A');
 assert.throws(()=>x.oauth.verifyAuthorization(signToken(x.k.kp,{sub:'faraday://lab/b'}),'mcp:tools:read'),/invalid_token/);
 assert.equal(x.oauth.verifyAuthorization(signToken(x.k.kp,{client_id:'client-B'}),'mcp:tools:read').clientId,'client-B');
});
test('missing jti and ledger faults deny; cannot silently fall back to allow',t=>{
 const x=fixture(t);assert.throws(()=>x.oauth.verifyAuthorization(signToken(x.k.kp,{jti:''}),'mcp:tools:read'),/invalid_token/);
 x.reader.close();assert.throws(()=>x.oauth.verifyAuthorization(signToken(x.k.kp),'mcp:tools:read'),/invalid_token/);
 // Avoid double closing in cleanup.
 x.reader.close=()=>{};
});
test('JWK rotation replaces trust atomically and rejects old signing key',t=>{
 const x=fixture(t),old=signToken(x.k.kp),next=key();next.jwk.kid='keyB';
 const newToken=signToken(next.kp,{kid:'keyB'});
 assert.throws(()=>x.oauth.replacePublicJwks([{...next.jwk,d:'bad'}]));
 assert.equal(x.oauth.verifyAuthorization(old,'mcp:tools:read').clientId,'client-A');
 x.oauth.replacePublicJwks([next.jwk]);
 assert.throws(()=>x.oauth.verifyAuthorization(old,'mcp:tools:read'),/invalid_token/);
 assert.equal(x.oauth.verifyAuthorization(newToken,'mcp:tools:read').clientId,'client-A');
});
test('revocation store fails closed on missing or symlinked file',t=>{
 const root=mkdtempSync(join(tmpdir(),'faraday-revocation-path-'));t.after(()=>rmSync(root,{recursive:true,force:true}));
 const db=join(root,'real.db');assert.throws(()=>new LocalOAuthRevocations(db),/missing/);
 const writer=new LocalOAuthRevocations(db,{create:true});writer.close();
 if(process.platform!=='win32'){const link=join(root,'link.db');symlinkSync(db,link);assert.throws(()=>new LocalOAuthRevocations(link),/unsafe/);}
});
