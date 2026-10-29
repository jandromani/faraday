import {test} from 'node:test';
import assert from 'node:assert/strict';
import {PassThrough} from 'node:stream';
import {createServer} from 'node:http';
import {mkdtempSync,writeFileSync,rmSync,chmodSync,mkdirSync,symlinkSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {forbiddenIp,validatedMcpUrl,pinnedAddress,secureMcpFetch} from '../lib/egress-guard.js';
import {ToolPolicy,loadToolPolicy} from '../lib/security-policy.js';
import {auditWorkspace} from '../lib/security-audit.js';
import {tapGuardedJsonLines} from '../lib/observe.js';
import {HttpBridge} from '../lib/http-bridge.js';

const policyData={version:1,mode:'enforce',allowedTools:{demo:['safe_read']},maxArgumentBytes:256};
const rpc=(id,name)=>({jsonrpc:'2.0',id,method:'tools/call',params:{name,arguments:{test:1}}});
const workspace=t=>{const dir=mkdtempSync(join(tmpdir(),'faraday-shield-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));return dir;};

test('shield rejects private, metadata and IPv6 mapped destinations',()=>{
  for(const ip of ['127.0.0.1','169.254.169.254','10.0.0.1','172.16.1.1',
    '192.168.0.1','100.100.100.200','::1','fc00::1','::ffff:127.0.0.1'])
    assert.equal(forbiddenIp(ip),true,ip);
  assert.equal(forbiddenIp('1.1.1.1'),false);
});
test('shield rejects remote HTTP, URL secrets and unapproved loopback aliases',()=>{
  for(const url of ['http://example.com/mcp','http://169.254.169.254/latest',
    'https://user:pass@example.com/mcp','https://example.com/mcp?token=secret',
    'http://foo.localhost/mcp','https://10.2.2.2/mcp'])
    assert.throws(()=>validatedMcpUrl(url),undefined,url);
});
test('shield DNS pinning rejects any mixed private result',async()=>{
  await assert.rejects(pinnedAddress('https://example.com/mcp',{resolver:async()=>[
    {address:'8.8.8.8',family:4},{address:'10.1.1.1',family:4}]}),/private/);
  assert.deepEqual(await pinnedAddress('https://example.com/mcp',{resolver:async()=>[
    {address:'1.1.1.1',family:4}]}),{address:'1.1.1.1',family:4});
});
test('shield bounds HTTP response content',async t=>{
  const app=createServer((_req,res)=>res.end('x'.repeat(1024)));
  await new Promise(r=>app.listen(0,'127.0.0.1',r));t.after(()=>app.close());
  const result=await secureMcpFetch('http://127.0.0.1:'+app.address().port+'/mcp',
    {method:'POST',body:'{}'},{maxBytes:100});
  await assert.rejects(result.text(),/size limit/);
});
test('shield policy is explicit and defaults to denying unknown tools',()=>{
  const policy=new ToolPolicy(policyData,'demo');
  assert.equal(policy.decision(rpc(1,'safe_read')).allowed,true);
  assert.equal(policy.decision(rpc(2,'delete_all')).allowed,false);
  assert.throws(()=>new ToolPolicy({version:1,mode:'enforce',allowedTools:{}},'demo'),/allowlist/);
});
test('shield stdio guard blocks denied calls without forwarding them',async()=>{
  const source=new PassThrough(),destination=new PassThrough(),replies=new PassThrough();
  let received='',blocked='';destination.on('data',x=>received+=x);replies.on('data',x=>blocked+=x);
  tapGuardedJsonLines(source,destination,{consume:()=>{}},new ToolPolicy(policyData,'demo'),replies);
  const allowed=JSON.stringify(rpc(1,'safe_read'))+'\n';
  source.end(allowed+JSON.stringify(rpc(2,'delete_all'))+'\n');
  await new Promise(r=>destination.once('end',r));
  assert.equal(received,allowed);
  assert.equal(JSON.parse(blocked).error.code,-32003);
});
test('shield HTTP bridge denies before contacting remote endpoint',async t=>{
  const dir=workspace(t),requests=[],emitted=[];
  const bridge=new HttpBridge({server:{name:'demo',url:'https://example.com/mcp',headers:{}},
    db:join(dir,'db.sqlite'),policy:new ToolPolicy(policyData,'demo'),
    fetcher:async x=>{requests.push(x);throw Error('must not fetch');},
    emit:x=>emitted.push(x)});
  await bridge.accept(JSON.stringify(rpc(3,'delete_all')));
  assert.equal(requests.length,0);
  assert.equal(JSON.parse(emitted[0]).error.code,-32003);
  await bridge.close();
});
test('shield local posture audit flags overpermissive private directory',{skip:process.platform==='win32'?'POSIX modes do not verify Windows ACLs':false},t=>{
  const dir=workspace(t);mkdirSync(join(dir,'.faraday'));chmodSync(join(dir,'.faraday'),0o755);
  assert.ok(auditWorkspace(dir).failures>0);
});
test('shield local posture audit does not treat unknown Windows ACLs as safe',{skip:process.platform!=='win32'},t=>{
  const dir=workspace(t),privateDir=join(dir,'.faraday'),backups=join(privateDir,'targets');
  mkdirSync(backups,{recursive:true});writeFileSync(join(privateDir,'graph.sqlite'),'');writeFileSync(join(backups,'backup.json'),'{}');
  const report=auditWorkspace(dir);
  for(const name of ['private-data-directory','graph-database','config-backup-directory']){
    const check=report.checks.find(item=>item.name===name);assert.equal(check.status,'review');assert.match(check.detail,/ACL not verified/);
  }
  assert.equal(report.overall,'review-required');assert.ok(report.reviews>=3);
});
test('shield audit CLI returns nonzero when review is required',t=>{
  const dir=workspace(t),cli=fileURLToPath(new URL('../bin/faraday.js',import.meta.url));
  const result=spawnSync(process.execPath,[cli,'security','audit','--root',dir],{encoding:'utf8'});
  assert.ifError(result.error);assert.equal(result.status,2,result.stderr);
  const report=JSON.parse(result.stdout);assert.equal(report.overall,'review-required');assert.ok(report.reviews>0);
});
test('shield audit rejects a dangling private directory link',t=>{
  const dir=workspace(t);
  try{symlinkSync(join(dir,'missing'),join(dir,'.faraday'),process.platform==='win32'?'junction':'dir');}
  catch(error){if(process.platform==='win32'&&error.code==='EPERM'){t.skip('Windows account cannot create symbolic links');return;}throw error;}
  const report=auditWorkspace(dir);
  assert.equal(report.checks.find(item=>item.name==='private-data-directory').status,'fail');
  assert.equal(report.overall,'needs-attention');
});
test('shield audit reports when backup inspection exceeds its limit',t=>{
  const dir=workspace(t),backups=join(dir,'.faraday','targets');mkdirSync(backups,{recursive:true});
  if(process.platform!=='win32')chmodSync(backups,0o700);
  for(let index=0;index<501;index++)writeFileSync(join(backups,String(index)),'',{mode:0o600});
  const report=auditWorkspace(dir);
  assert.ok(report.checks.some(item=>item.name==='private-backup-file'&&item.status==='review'&&/500/.test(item.detail)));
  assert.notEqual(report.overall,'no-local-issues-detected');
});
