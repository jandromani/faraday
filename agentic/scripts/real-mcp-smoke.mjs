/** Live stdio checks against official MCP servers installed in an isolated temp prefix by CI.
 * Never writes to the fixture directory via MCP, and never logs tool results. */
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {probeStdio} from '../lib/mcp-live-probe.js';
const prefix=process.env.FARADAY_MCP_FIXTURES;
if(!prefix)throw Error('FARADAY_MCP_FIXTURES is required (CI installs external packages explicitly)');
function executable(name){
 const dir=join(prefix,'node_modules','@modelcontextprotocol',name);
 const p=JSON.parse(readFileSync(join(dir,'package.json'),'utf8'));
 const binary=typeof p.bin==='string'?p.bin:Object.values(p.bin||{})[0];
 if(!binary)throw Error('Official MCP server missing CLI bin');
 return resolve(dir,binary);
}
const root=mkdtempSync(join(tmpdir(),'faraday-real-mcp-'));
try{
 const allowed=join(root,'allowed');mkdirSync(allowed);
 const serverCfg={mcpServers:{
   filesystem:{command:process.execPath,args:[executable('server-filesystem'),allowed]},
   everything:{command:process.execPath,args:[executable('server-everything'),'stdio']}
 }};
 const config=join(root,'mcp.json');writeFileSync(config,JSON.stringify(serverCfg));
 const evidence=[];
 for(const name of ['filesystem','everything'])for(const protocol of ['modern','legacy']){
  const report=await probeStdio({configFile:config,server:name,protocol,timeoutMs:30000,maxPages:15});
  if(report.result!=='pass'||report.toolsObserved<1||report.truncated)throw Error(`Unexpected MCP ${name}/${protocol} response`);
  evidence.push({server:name,era:report.era,version:report.protocolVersion,toolsObserved:report.toolsObserved,
    elapsedMs:report.elapsedMs,pages:report.pages,invokedTools:report.invokedTools});
 }
 // Explicit read-only tool smoke: all write tools remain untouched.
 const check=await probeStdio({configFile:config,server:'filesystem',protocol:'modern',timeoutMs:30000,
   callTool:'list_allowed_directories',allowCall:true});
 if(!check.toolCall?.success)throw Error('Official filesystem read-only tool failed');
 console.log(JSON.stringify({kind:'faraday-mcp-official-smoke',result:'pass',
  fixtureVersions:{filesystem:'2.0.1',everything:'2.0.1'},
  evidence,readOnlyCall:'list_allowed_directories',
  scope:'stdio versions + tools/list + explicitly opted-in read-only filesystem tool; no claims about all MCP features'},null,2));
}finally{rmSync(root,{recursive:true,force:true});}
