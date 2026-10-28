#!/usr/bin/env node
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { discover, readMcpConfig, configServers } from '../lib/discover.js';
import { GraphStore, toMermaid } from '../lib/store.js';
import { proxyMcp } from '../lib/proxy.js';
import { serveGraph } from '../lib/server.js';
import { installProxy, uninstallProxy } from '../lib/install.js';
import { runDemo } from '../lib/demo.js';
import { doctor, initialize } from '../lib/setup.js';
import { compareSnapshots, readSnapshot, snapshotFromStore, saveSnapshot, generateRegressionTests } from '../lib/contracts.js';

const appPath = fileURLToPath(import.meta.url);
const usage = `FARADAY Graph 0.4.0 — local MCP discovery, observation, contracts and setup

Usage:
  faraday scan [--root PATH] [--db PATH] [--include-global] [--json]
  faraday graph [--db PATH] [--format json|mermaid]
  faraday proxy --config FILE --server NAME [--db PATH] [--debug-stderr]
  faraday hook --config FILE --server NAME [--db PATH]
  faraday install --config FILE --server NAME [--db PATH]
  faraday uninstall --config FILE --server NAME
  faraday serve [--db PATH] [--port 0]
  faraday doctor [--root PATH] [--json]
  faraday init [--root PATH] [--dry-run]
  faraday contracts snapshot [--db PATH] --out FILE
  faraday contracts compare --base FILE --current FILE [--json] [--fail-on-breaking]
  faraday contracts generate --base FILE --current FILE --out DIR
  faraday demo

Only 'proxy' launches a configured MCP server. 'install' rewrites the selected
strict-JSON server entry (reversible with 'uninstall') and stores a private
mode-0600 backup containing the original config. 'hook' never changes files.
Neither scan nor serve executes MCP tools.
`;
function argsOf(args) {
  const out = { _:[] };
  for (let i=0;i<args.length;i++) {
    const t=args[i];
    if (!t.startsWith('--')) {out._.push(t);continue;}
    const key=t.slice(2);
    if (['include-global','json','debug-stderr','dry-run','fail-on-breaking'].includes(key)) {out[key]=true;continue;}
    if (!['root','db','format','config','server','port','out','base','current'].includes(key)) throw new Error('Unknown option');
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
  if (cmd==='doctor') {
    const result=doctor({root:flags.root,includeGlobal:!!flags['include-global']});
    if(flags.json) process.stdout.write(JSON.stringify(result,null,2)+'\n');
    else process.stdout.write('FARADAY DOCTOR\n'+result.checks.map(c=>`  ${c.ok?'OK':'WARN'}  ${c.name}: ${c.detail}\n`).join('')+
      result.warnings.map(w=>'  warning: '+w+'\n').join('')+`  Ready for initial graph: ${result.ready}\n`);
  } else if (cmd==='init') {
    const result=initialize({root:flags.root,dryRun:!!flags['dry-run']});
    process.stdout.write(JSON.stringify(result,null,2)+'\n');
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
    proxyMcp({configFile:flags.config,server:flags.server,database:fileDB(flags),debugStderr:!!flags['debug-stderr']});
  } else if (cmd==='hook') {
    if (!flags.config || !flags.server) throw Error('hook needs --config and --server');
    const found=configServers(readMcpConfig(resolve(flags.config))).find(x=>x.name===flags.server);
    if (!found || found.transport!=='stdio') throw Error('Only named stdio servers can be wrapped');
    process.stdout.write(JSON.stringify({
      command:process.execPath,
      args:[appPath,'proxy','--config',resolve(flags.config),'--server',flags.server,'--db',fileDB(flags)]
    },null,2)+'\n');
  } else if (cmd==='install') {
    const out=installProxy({configFile:flags.config,server:flags.server,db:fileDB(flags),binPath:appPath,nodePath:process.execPath});
    process.stdout.write(`Installed FARADAY proxy for ${out.server} (uninstall is available).\n`);
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
