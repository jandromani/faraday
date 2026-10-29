/** Cross-OS cold installation + rollback smoke; runs with a packed local tarball. */
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,dirname} from 'node:path';
import {spawnSync} from 'node:child_process';
import {performance} from 'node:perf_hooks';
const root=mkdtempSync(join(tmpdir(),'faraday-onboard-'));
const packageRoot=resolve(import.meta.dirname,'..');
const time=performance.now();
const npmScript=join(dirname(process.execPath),'node_modules','npm','bin','npm-cli.js');
const npmCommand=existsSync(npmScript)?process.execPath:(process.platform==='win32'?'cmd.exe':'npm');
function npmArgs(args){return existsSync(npmScript)?[npmScript,...args]:(process.platform==='win32'?['/d','/c','npm',...args]:args);}
function run(command,args,{cwd=packageRoot}={}){
 const result=spawnSync(command,args,{cwd,encoding:'utf8',timeout:60000,env:{...process.env,npm_config_audit:'false',npm_config_fund:'false'}});
 if(result.status!==0)throw Error(`Onboarding subprocess failed: ${args[0]}`);
 return result.stdout;
}
try{
 const cache=join(root,'package');mkdirSync(cache);
 const pack=run(npmCommand,npmArgs(['pack','--json','--pack-destination',cache]));
 const tar=JSON.parse(pack)[0]?.filename;
 if(!tar||!existsSync(join(cache,tar)))throw Error('npm pack not found');
 const prefix=join(root,'prefix');mkdirSync(prefix);
 run(npmCommand,npmArgs(['install','--offline','--ignore-scripts','--no-audit','--no-fund','--prefix',prefix,join(cache,tar)]));
 const cli=join(prefix,'node_modules','@faraday','agentic','bin','faraday.js');
 if(!existsSync(cli))throw Error('Installed CLI missing');
 const work=join(root,'workspace');mkdirSync(work);
 const conf=join(work,'.mcp.json');const orig={mcpServers:{fixture:{command:process.execPath,args:['--version']}}};
 writeFileSync(conf,JSON.stringify(orig));
 run(process.execPath,[cli,'init','--root',work]);
 const before=readFileSync(conf,'utf8');
 let automaticInstall;
 if(process.platform==='win32'){
  run(process.execPath,[cli,'install','--config',conf,'--server','fixture','--dry-run']);
  if(readFileSync(conf,'utf8')!==before||existsSync(join(work,'.faraday','targets')))throw Error('Dry-run changed the config or created a backup');
  const blocked=spawnSync(process.execPath,[cli,'install','--config',conf,'--server','fixture'],{cwd:work,encoding:'utf8',timeout:60000});
  if(blocked.status!==1||!blocked.stderr.includes('[FARADAY] Command failed.'))throw Error('Windows install was not rejected by the CLI');
  if(readFileSync(conf,'utf8')!==before||existsSync(join(work,'.faraday','targets')))throw Error('Blocked install changed the config or created a backup');
  automaticInstall='blocked-unverified-acl';
 }else{
  run(process.execPath,[cli,'install','--config',conf,'--server','fixture']);
  if(readFileSync(conf,'utf8')===before)throw Error('Install did not wrap the config');
  run(process.execPath,[cli,'uninstall','--config',conf,'--server','fixture']);
  if(JSON.stringify(JSON.parse(readFileSync(conf,'utf8')))!==JSON.stringify(orig))throw Error('Uninstall did not restore exact server entry');
  automaticInstall='installed-and-rolled-back';
 }
 const check=JSON.parse(run(process.execPath,[cli,'doctor','--root',work,'--json']));
 if(!check.ready)throw Error('Onboarding doctor did not confirm readiness');
 console.log(JSON.stringify({kind:'faraday-cold-install',result:'pass',platform:process.platform,
   node:process.versions.node,elapsedMs:Math.round(performance.now()-time),
  automaticInstall,source:process.platform==='win32'?'npm pack -> npm install --offline -> init -> dry-run -> blocked install -> doctor':'npm pack -> npm install --offline -> init -> install -> uninstall -> doctor',
   scope:'local test workspace only; no production MCP client'},null,2));
}finally{rmSync(root,{recursive:true,force:true});}
