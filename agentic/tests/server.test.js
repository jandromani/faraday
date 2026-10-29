import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { serveGraph } from '../lib/server.js';
import http from 'node:http';

test('viewer is localhost, token gated, and returns metadata-only graph',async t=>{
 const dir=mkdtempSync(join(tmpdir(),'faraday-view-'));
 const {server,port,token}=await serveGraph({database:join(dir,'graph.sqlite')});
 t.after(async()=>{await new Promise(resolve=>server.close(resolve));rmSync(dir,{recursive:true,force:true});});
 const origin=`http://127.0.0.1:${port}`;
 const no=await fetch(origin+'/');assert.equal(no.status,403);
 const unicode=await fetch(origin+'/?key='+encodeURIComponent('é'.repeat(token.length)));
 assert.equal(unicode.status,403);
 const start=await fetch(origin+'/?key='+token,{redirect:'manual'});
 assert.equal(start.status,302);
 const cookie=start.headers.get('set-cookie').split(';')[0];
 const page=await fetch(origin+'/',{headers:{cookie}});
 assert.equal(page.status,200);assert.match(await page.text(),/FARADAY/);
 assert.ok((await fetch(origin+'/app.js',{headers:{cookie}})).ok);
 const contracts=await fetch(origin+'/api/contracts',{headers:{cookie}});
 assert.equal(contracts.status,200);assert.deepEqual((await contracts.json()).tools,[]);
 const graph=await fetch(origin+'/api/graph',{headers:{cookie}});
 assert.deepEqual((await graph.json()).stats,{nodes:0,edges:0,events:0,toolCalls:0,contracts:0});
 const badHostStatus=await new Promise((resolve,reject)=>{
  const req=http.get({hostname:'127.0.0.1',port,path:'/api/graph',headers:{Cookie:cookie,Host:'attacker.example'}},r=>{r.resume();resolve(r.statusCode)});req.on('error',reject);
 });
 assert.equal(badHostStatus,403);
 assert.equal((await fetch(origin+'/api/graph',{method:'POST',headers:{cookie}})).status,405);
});
