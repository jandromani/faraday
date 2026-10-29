import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import http from 'node:http';
import {fileURLToPath} from 'node:url';
import {join,dirname} from 'node:path';

const executable=fileURLToPath(new URL('../scripts/vault-dev-smoke.mjs',import.meta.url));
const bootstrap='faraday-local-mock-bootstrap-123';
const sample=()=>new Promise((resolve,reject)=>{
 const state={secrets:new Map(),tokens:new Set(),serial:0,events:[],allowAdmin:false};
 const server=http.createServer(async(req,res)=>{
  const chunks=[];for await(const b of req)chunks.push(b);
  const body=chunks.length?JSON.parse(Buffer.concat(chunks).toString('utf8')):{};
  const url=new URL(req.url,'http://127.0.0.1');
  const path=url.pathname,who=req.headers['x-vault-token'],root=who===bootstrap,scoped=state.tokens.has(who);
  const answer=(status,payload={})=>{res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(payload));};
  state.events.push({method:req.method,path,root,scoped});
  if(path==='/v1/sys/health')return answer(200,{initialized:true});
  if(path==='/v1/auth/approle/login'&&req.method==='POST'){
   if(body.role_id!=='local-test-role'||!String(body.secret_id).startsWith('secret-'))return answer(403);
   const token='scoped-test-token-'+(++state.serial)+'-safe';
   state.tokens.add(token);return answer(200,{auth:{client_token:token}});
  }
  if(path==='/v1/secret/data/gateway/backend'&&req.method==='GET'&&scoped)
   return answer(200,{data:{data:{backend_credential:state.secrets.get(path)},metadata:{version:1}}});
  if(path.startsWith('/v1/secret/data/')&&req.method==='GET')return answer(root?200:403);
  if(path==='/v1/sys/mounts')return answer(root||state.allowAdmin?200:403);
  if(!root)return answer(403);
  if(path==='/v1/sys/policies/acl/faraday-gateway'&&req.method==='PUT'){
   if(!body.policy?.includes('capabilities = ["read"]'))return answer(400);
   return answer(204);
  }
  if(path==='/v1/sys/auth/approle'&&req.method==='POST')return answer(204);
  if(path==='/v1/auth/approle/role/faraday-gateway'&&req.method==='POST'){
   if(body.token_no_default_policy!==true||body.secret_id_num_uses!==1)return answer(400);
   return answer(204);
  }
  if(path==='/v1/auth/approle/role/faraday-gateway/role-id')return answer(200,{data:{role_id:'local-test-role'}});
  if(path==='/v1/auth/approle/role/faraday-gateway/secret-id'&&req.method==='POST')
   return answer(200,{data:{secret_id:'secret-'+(++state.serial)+'-random'}});
  if(path.startsWith('/v1/secret/data/')&&req.method==='POST'){
   state.secrets.set(path,body.data?.backend_credential);return answer(200,{data:{version:1}});
  }
  if(path==='/v1/auth/token/revoke'&&req.method==='POST'){
   state.tokens.delete(body.token);return answer(204);
  }
  return answer(404);
 });
 server.listen(0,'127.0.0.1',()=>resolve({server,state,url:'http://127.0.0.1:'+server.address().port}));
 server.on('error',reject);
});
async function run(t,{allowAdmin=false}={}){
 const fixture=await sample();fixture.state.allowAdmin=allowAdmin;
 t.after(()=>new Promise(resolve=>fixture.server.close(resolve)));
 return new Promise((resolve,reject)=>{
  const child=spawn(process.execPath,[executable],{env:{...process.env,
   FARADAY_TEST_VAULT_URL:fixture.url,FARADAY_TEST_VAULT_TOKEN:bootstrap},
   stdio:['ignore','pipe','pipe']});
  let stdout='',stderr='';child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);
  child.on('error',reject);child.on('close',code=>resolve({code,stdout,stderr,state:fixture.state}));
 });
}
test('AppRole protocol smoke proves scoped reads and revoked tokens, no root token in workload',async t=>{
 const r=await run(t);assert.equal(r.code,0,r.stderr);
 const output=JSON.parse(r.stdout.trim());
 assert.equal(output.result,'pass');
 assert.equal(output.controls.length,8);
 assert.equal(r.state.tokens.size,0);
 assert.equal(r.state.events.filter(x=>x.path==='/v1/sys/mounts'&&x.scoped).length,1);
 assert.equal(r.state.events.filter(x=>x.path==='/v1/auth/approle/login').length,2);
 assert.ok(!r.stdout.includes('scoped-test-token'));
});
test('AppRole smoke fails closed when a restricted token can access admin endpoints',async t=>{
 const r=await run(t,{allowAdmin:true});
 assert.notEqual(r.code,0);
 assert.match(r.stderr,/unexpected status during deny-admin/i);
 assert.doesNotMatch(r.stderr,/scoped-test-token/);
});
