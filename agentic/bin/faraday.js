#!/usr/bin/env node
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { discover, readMcpConfig, configServers } from '../lib/discover.js';
import { GraphStore, toMermaid } from '../lib/store.js';
import { proxyMcp } from '../lib/proxy.js';
import { bridgeMcp, configuredHttpServer } from '../lib/http-bridge.js';
import { serveGraph } from '../lib/server.js';
import { installProxy, uninstallProxy } from '../lib/install.js';
import { runDemo } from '../lib/demo.js';
import { doctor, initialize } from '../lib/setup.js';
import { compareSnapshots, readSnapshot, snapshotFromStore, saveSnapshot, generateRegressionTests } from '../lib/contracts.js';
import { fetchFreeModels, explainFree, graphFromDatabase, makeContractAdvisoryData } from '../lib/ai-free.js';
import {auditWorkspace} from '../lib/security-audit.js';
import {DUMMY_AGENTS, DISTRIBUTION, runLab, labConfig} from '../lib/lab.js';
import {diffAuthority, readPolicy, affectedClients} from '../lib/trust-diff.js';
import {compatibilityReport} from '../lib/compatibility.js';
import {runAuthorityDemo,runAuthorityEvaluations} from '../lib/authority-demo.js';
import {writeFileSync, mkdirSync} from 'node:fs';

const appPath = fileURLToPath(import.meta.url);
const usage = `FARADAY Graph 0.9.0 — local MCP discovery, observation, contracts and setup

Usage:
  faraday scan [--root PATH] [--db PATH] [--include-global] [--json]
  faraday graph [--db PATH] [--format json|mermaid]
  faraday proxy --config FILE --server NAME [--db PATH] [--debug-stderr] [--policy FILE]
  faraday bridge --config FILE --server NAME [--db PATH] [--policy FILE]
  faraday hook --config FILE --server NAME [--db PATH]
  faraday install --config FILE --server NAME [--db PATH] [--dry-run] [--policy FILE]
  faraday uninstall --config FILE --server NAME
  faraday serve [--db PATH] [--port 0]
  faraday doctor [--root PATH] [--json]
  faraday onboard [--root PATH] [--json]
  faraday init [--root PATH] [--dry-run]
  faraday contracts snapshot [--db PATH] --out FILE
  faraday contracts compare --base FILE --current FILE [--json] [--fail-on-breaking]
  faraday contracts generate --base FILE --current FILE --out DIR
  faraday ai models
  faraday ai graph [--db PATH] [--send-metadata] [--model FREE_MODEL]
  faraday ai contracts --base FILE --current FILE [--send-metadata] [--model FREE_MODEL]
  faraday lab agents [--json]
  faraday lab run [--seed 42] [--limit 1000] [--out FILE] [--fail-on-gap]
  faraday lab fixture --out DIR
  faraday compat [--root PATH] [--include-global] [--json]
  faraday trust diff --base POLICY --current POLICY [--db PATH] [--fail-on-expansion]
  faraday authority demo # synthetic end-to-end gateway authorization
  faraday authority eval [--limit 100] [--out FILE]
  faraday demo
  faraday security policy-template --server NAME [--json]
  faraday security audit [--root PATH] [--json]

Only 'proxy' launches a local MCP server. 'bridge' connects to a pinned
HTTPS or loopback Streamable HTTP endpoint. 'install' rewrites the selected
strict-JSON server entry (reversible with 'uninstall') and stores a private
mode-0600 backup containing the original config. 'hook' never changes files.
Neither scan nor serve executes MCP tools. AI is optional, advisory-only
and requires explicit consent to send graph metadata to a free model.
`;
function argsOf(args) {
  const out = { _:[] };
  for (let i=0;i<args.length;i++) {
    const t=args[i];
    if (!t.startsWith('--')) {out._.push(t);continue;}
    const key=t.slice(2);
    if (['include-global','json','debug-stderr','dry-run','fail-on-breaking','send-metadata','fail-on-gap','fail-on-expansion'].includes(key)) {out[key]=true;continue;}
    if (!['root','db','format','config','server','port','out','base','current','model','policy','seed','limit'].includes(key)) throw new Error('Unknown option');
    if (i+1>=args.length || args[i+1].startsWith('--')) throw new Error('Missing option value');
    out[key]=args[++i];
  }
  return out;
}
const fileDB=(flags)=>resolve(flags.db || resolve(flags.root||process.cwd(),'.faraday/graph.sqlite'));
async function main() {
  const [cmd,...argv]=process.argv.slice(2);
  const flags=argsOf(argv);
  if (!cmd || cmd === 'help' || cmd === '--help') {process.stdout.write(usage);return;}
  if(cmd==='authority') {
    const action=flags._[0];
    if(action==='demo'){
      const report=await runAuthorityDemo();
      process.stdout.write(JSON.stringify(report,null,2)+'\n');
      if(!report.success)process.exitCode=2;
    } else if(action==='eval'){
      const report=runAuthorityEvaluations({count:flags.limit===undefined?100:Number(flags.limit)});
      if(flags.out)writeFileSync(resolve(flags.out),JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
      process.stdout.write(JSON.stringify({format:report.format,version:report.version,summary:report.summary},null,2)+'\n');
      if(report.summary.failed)process.exitCode=2;
    } else throw Error('Use authority demo or authority eval');
  } else if(cmd==='lab') {
    const action=flags._[0];
    if(action==='fixture') {
      if(!flags.out)throw Error('lab fixture requires --out directory');
      const dir=resolve(flags.out);mkdirSync(dir,{recursive:true,mode:0o700});
      const conf=labConfig({serverScript:resolve(dirname(appPath),'faraday-lab-server.js')});
      writeFileSync(join(dir,'mcp.json'),JSON.stringify(conf,null,2)+'\n',{mode:0o600,flag:'wx'});
      writeFileSync(join(dir,'agents.json'),JSON.stringify(DUMMY_AGENTS,null,2)+'\n',{mode:0o600,flag:'wx'});
      process.stdout.write(JSON.stringify({kind:'synthetic',config:join(dir,'mcp.json'),agents:DUMMY_AGENTS.length},null,2)+'\n');
    } else if(action==='agents') {
      process.stdout.write(JSON.stringify({kind:'synthetic-offline',agents:DUMMY_AGENTS},null,2)+'\n');
    } else if(action==='run') {
      const seed=flags.seed===undefined?42:Number(flags.seed),limit=flags.limit===undefined?1000:Number(flags.limit);
      const report=runLab({seed,limit,includeCases:!!flags.out});
      if(flags.out){
        const target=resolve(flags.out);
        if(!target.endsWith('.json'))throw Error('Lab output must be a JSON file');
        writeFileSync(target,JSON.stringify(report,null,2)+'\n',{encoding:'utf8',mode:0o600,flag:'wx'});
      }
      const output=flags.out?{...report,cases:undefined}:report;
      process.stdout.write(JSON.stringify(output,null,2)+'\n');
      if(report.summary.failed || (flags['fail-on-gap']&&report.summary.gaps))process.exitCode=2;
    } else throw Error('Use lab agents or lab run');
  } else if(cmd==='compat') {
    process.stdout.write(JSON.stringify(compatibilityReport({root:flags.root,includeGlobal:!!flags['include-global']}),null,2)+'\n');
  } else if(cmd==='trust') {
    if(flags._[0]!=='diff'||!flags.base||!flags.current)throw Error('Use trust diff --base --current');
    const report=diffAuthority(readPolicy(flags.base),readPolicy(flags.current));
    if(flags.db){const store=new GraphStore(fileDB(flags));
      try { const graph=store.snapshot();report.added=report.added.map(e=>({...e,potentialClients:affectedClients(graph,e.server)})); }
      finally{store.close();}
    }
    process.stdout.write(JSON.stringify(report,null,2)+'\n');
    if(flags['fail-on-expansion']&&report.summary.authorityExpanded)process.exitCode=2;
  } else if(cmd==='security') {
    if(flags._[0]==='audit'){
      const report=auditWorkspace(flags.root||process.cwd());
      process.stdout.write(JSON.stringify(report,null,2)+'\n');
      if(report.failures)process.exitCode=2;
    } else if(flags._[0]==='policy-template'&&flags.server){
      process.stdout.write(JSON.stringify({version:1,mode:'enforce',maxArgumentBytes:8192,allowedTools:{[flags.server]:[]}},null,2)+'\n');
    } else throw Error('Use security audit or policy-template --server NAME');
  } else if (cmd==='doctor') {
    const result=doctor({root:flags.root,includeGlobal:!!flags['include-global']});
    if(flags.json) process.stdout.write(JSON.stringify(result,null,2)+'\n');
    else process.stdout.write('FARADAY DOCTOR\n'+result.checks.map(c=>`  ${c.ok?'OK':'WARN'}  ${c.name}: ${c.detail}\n`).join('')+
      result.warnings.map(w=>'  warning: '+w+'\n').join('')+`  Ready for initial graph: ${result.ready}\n`);
  } else if (cmd==='onboard') {
    const result=doctor({root:flags.root,includeGlobal:!!flags['include-global']});
    const suggestions=result.servers.map(s=>{
      const location=s.source.startsWith('workspace:') ? resolve(result.root,s.source.slice(10)) : null;
      return {client:s.client,server:s.server,transport:s.transport,configFile:location,
        steps:s.transport==='sse' ? ['Migrate legacy HTTP+SSE server to Streamable HTTP'] :
          location ? [
            ['faraday','install','--dry-run','--config',location,'--server',s.server],
            ['faraday','install','--config',location,'--server',s.server],
            ['faraday','serve']
          ] : ['Find the source configuration file and use faraday hook (read-only)']};
    });
    process.stdout.write(JSON.stringify({ready:result.ready,checks:result.checks,warnings:result.warnings,suggestions},null,2)+'\n');
  } else if (cmd==='init') {
    const result=initialize({root:flags.root,dryRun:!!flags['dry-run'],policyFile:flags.policy});
    process.stdout.write(JSON.stringify(result,null,2)+'\n');
  } else if (cmd==='ai') {
    const action=flags._[0];
    if (action==='models') {
      const models=await fetchFreeModels();
      process.stdout.write(JSON.stringify({provider:'openrouter',freeOnly:true,models},null,2)+'\n');
    } else if (action==='graph' || action==='contracts') {
      const metadata=action==='graph' ? graphFromDatabase(fileDB(flags)) :
        (()=>{if(!flags.base||!flags.current) throw Error('ai contracts needs --base and --current');
           return makeContractAdvisoryData(flags.base,flags.current);})();
      if (!flags['send-metadata']) {
        process.stdout.write(JSON.stringify({mode:'offline-preview',metadata,
          note:'No external request sent. Add --send-metadata after reviewing and approving this metadata.'},null,2)+'\n');
      } else {
        process.stderr.write('[FARADAY] Sending graph/contract metadata to an OpenRouter free model (not agent prompts, arguments or tool results).\n');
        const result=await explainFree({metadata,model:flags.model||'openrouter/free',consent:true});
        process.stdout.write(JSON.stringify(result,null,2)+'\n');
      }
    } else throw Error('Unknown AI command');
  } else if (cmd==='contracts') {
    const action=flags._[0];
    if(action==='snapshot') {
      if(!flags.out) throw Error('snapshot needs --out');
      const store=new GraphStore(fileDB(flags));
      try {const data=snapshotFromStore(store);saveSnapshot(flags.out,data);
        process.stdout.write(`Saved ${data.tools.length} observed tool contracts to ${resolve(flags.out)}\n`);
      } finally{store.close();}
    } else if (action==='compare') {
      if(!flags.base||!flags.current)throw Error('compare needs --base and --current');
      const report=compareSnapshots(readSnapshot(flags.base),readSnapshot(flags.current));
      if(flags.json)process.stdout.write(JSON.stringify(report,null,2)+'\n');
      else process.stdout.write(`FARADAY Contracts: ${report.summary.breaking} breaking, ${report.summary.review} review, ${report.summary.additive} additive\n`+
        report.entries.flatMap(e=>e.changes.map(c=>`  ${c.severity.toUpperCase()} ${e.server}/${e.tool} ${c.path}: ${c.message}; potential clients: ${e.potentialClients.join(',')||'unknown'}\n`)).join(''));
      if(flags['fail-on-breaking'] && report.summary.breaking)process.exitCode=2;
    } else if(action==='generate') {
      if(!flags.base||!flags.current||!flags.out)throw Error('generate needs --base --current --out');
      process.stdout.write(JSON.stringify(generateRegressionTests({baseline:flags.base,current:flags.current,outDir:flags.out}),null,2)+'\n');
    } else throw Error('Unknown contracts subcommand');
  } else if (cmd==='scan') {
    const report=discover({root:flags.root,includeGlobal:!!flags['include-global']});
    const store=new GraphStore(fileDB(flags));
    try {store.inventory(report.servers);} finally {store.close();}
    if (flags.json) process.stdout.write(JSON.stringify({servers:report.servers,warnings:report.warnings},null,2)+'\n');
    else process.stdout.write(`FARADAY scan: ${report.servers.length} server configurations found\n`+
      report.servers.map(e=>`  ${e.client} → ${e.server} [${e.transport}]\n`).join('')+
      report.warnings.map(w=>`  warning: ${w}\n`).join('')+
      `Graph database: ${fileDB(flags)}\n`);
  } else if (cmd==='graph') {
    const store=new GraphStore(fileDB(flags));
    try {
      const data=store.snapshot();
      process.stdout.write(flags.format==='mermaid' ? toMermaid(data) : JSON.stringify(data,null,2)+'\n');
    } finally {store.close();}
  } else if (cmd==='proxy') {
    proxyMcp({configFile:flags.config,server:flags.server,database:fileDB(flags),debugStderr:!!flags['debug-stderr'],policyFile:flags.policy});
  } else if (cmd==='bridge') {
    await bridgeMcp({configFile:flags.config,server:flags.server,database:fileDB(flags),policyFile:flags.policy});
  } else if (cmd==='hook') {
    if (!flags.config || !flags.server) throw Error('hook needs --config and --server');
    const found=configServers(readMcpConfig(resolve(flags.config))).find(x=>x.name===flags.server);
    if (!found || found.transport==='sse') throw Error('Only named stdio or Streamable HTTP servers can be wrapped');
    if(found.transport==='http') configuredHttpServer(resolve(flags.config),flags.server);
    process.stdout.write(JSON.stringify({
      command:process.execPath,
      args:[appPath,found.transport==='http'?'bridge':'proxy','--config',resolve(flags.config),'--server',flags.server,'--db',fileDB(flags),...(flags.policy?['--policy',resolve(flags.policy)]:[])]
    },null,2)+'\n');
  } else if (cmd==='install') {
    const out=installProxy({configFile:flags.config,server:flags.server,db:fileDB(flags),binPath:appPath,nodePath:process.execPath,dryRun:!!flags['dry-run'],policyFile:flags.policy});
    process.stdout.write((flags['dry-run']?'Plan only':'Installed')+` FARADAY ${out.transport} adapter for ${out.server} (uninstall is available).\n`);
  } else if (cmd==='uninstall') {
    const out=uninstallProxy({configFile:flags.config,server:flags.server});
    process.stdout.write(`Uninstalled FARADAY proxy for ${out.server}; original entry restored.\n`);
  } else if (cmd==='serve') {
    if (flags.port!=null && (!/^\d+$/.test(flags.port) || +flags.port>65535)) throw Error('Invalid port');
    await serveGraph({database:fileDB(flags),port:flags.port==null?0:+flags.port,
      onReady:(url)=>process.stdout.write(`FARADAY Graph: ${url}\n`)});
  } else if (cmd==='demo') {
    const stats=await runDemo(fileDB(flags),appPath);
    process.stdout.write(`Demo completed: ${stats.nodes} nodes, ${stats.edges} edges, ${stats.toolCalls} tool calls.\nOpen the graph with: faraday serve --db ${fileDB(flags)}\n`);
  } else throw new Error('Unknown command');
}
main().catch(() => {process.stderr.write('[FARADAY] Command failed. Check options and local configuration.\n');process.exitCode=1;});
