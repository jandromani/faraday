import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createRequire} from 'node:module';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {GraphStore} from '../lib/store.js';

const prefix=process.env.FARADAY_MCP_FIXTURES;
if(!prefix)throw Error('FARADAY_MCP_FIXTURES is required');
const require=createRequire(join(resolve(prefix),'package.json'));
const {Client}=await import(pathToFileURL(require.resolve('@modelcontextprotocol/sdk/client/index.js')).href);
const {StdioClientTransport}=await import(pathToFileURL(require.resolve('@modelcontextprotocol/sdk/client/stdio.js')).href);
const serverDir=join(prefix,'node_modules','@modelcontextprotocol','server-filesystem');
const serverPackage=JSON.parse(readFileSync(join(serverDir,'package.json'),'utf8'));
const sdkPackage=JSON.parse(readFileSync(join(prefix,'node_modules','@modelcontextprotocol','sdk','package.json'),'utf8'));
if(serverPackage.version!=='2.0.1'||sdkPackage.version!=='1.32.2')throw Error('Unexpected MCP fixture versions');
const binary=typeof serverPackage.bin==='string'?serverPackage.bin:Object.values(serverPackage.bin||{})[0];
if(!binary)throw Error('Official MCP server missing CLI bin');
const root=mkdtempSync(join(tmpdir(),'faraday-client-mcp-'));
let client;
try{
 const allowed=join(root,'allowed');mkdirSync(allowed);
 const config=join(root,'mcp.json');writeFileSync(config,JSON.stringify({mcpServers:{filesystem:{command:process.execPath,args:[resolve(serverDir,binary),allowed]}}}));
 const cli=fileURLToPath(new URL('../bin/faraday.js',import.meta.url));
 let negotiatedVersion=null;
 const transport=new StdioClientTransport({command:process.execPath,args:[cli,'proxy','--config',config,'--server','filesystem','--db',join(root,'graph.sqlite')],stderr:'ignore'});
 transport.setProtocolVersion=version=>{negotiatedVersion=version;};
 client=new Client({name:'faraday-compatibility-test',version:'1.0.0'},{capabilities:{}});
 await client.connect(transport,{timeout:15000});
 const tools=await client.listTools(undefined,{timeout:15000});
 if(!tools.tools.some(tool=>tool.name==='list_allowed_directories'))throw Error('Read-only tool not listed');
 const result=await client.callTool({name:'list_allowed_directories',arguments:{}},undefined,{timeout:15000});
 if(result.isError||!Array.isArray(result.content)||!result.content.length)throw Error('Read-only call failed');
 let recorded={contracts:0,calls:0};
 // The MCP result may reach the SDK before the proxy's separate SQLite writer flushes.
 // Wait only for the *actual persisted* result; never synthesize evidence.
 for(let attempt=0;attempt<40;attempt++){
  const graph=new GraphStore(join(root,'graph.sqlite'));
  try{
   recorded={contracts:graph.db.prepare("SELECT COUNT(*) AS n FROM contracts WHERE server='filesystem' AND tool='list_allowed_directories'").get().n,
    calls:graph.db.prepare("SELECT COUNT(*) AS n FROM events WHERE server='filesystem' AND tool='list_allowed_directories' AND kind='tool_call' AND direction='response' AND status='ok'").get().n};
  }finally{graph.close();}
  if(recorded.contracts===1&&recorded.calls===1)break;
  if(recorded.contracts>1||recorded.calls>1)break;
  await new Promise(resolve=>setTimeout(resolve,75));
 }
 if(recorded.contracts!==1||recorded.calls!==1)throw Error('Proxy did not persist exactly one read-only contract and response');
 console.log(JSON.stringify({kind:'faraday-real-mcp-client-smoke',result:'pass',platform:process.platform,node:process.version,
  clientVersion:sdkPackage.version,serverVersion:serverPackage.version,transport:'stdio',negotiatedVersion,toolsObserved:tools.tools.length,
  readOnlyCall:'list_allowed_directories',recorded,scope:'official SDK client through FARADAY proxy to official filesystem server; not full conformance'},null,2));
}finally{try{await client?.close();}finally{rmSync(root,{recursive:true,force:true});}}