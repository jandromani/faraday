import { spawn } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { getExecutableServer } from './discover.js';
import { GraphStore } from './store.js';
import { McpObserver, tapJsonLines, tapGuardedJsonLines } from './observe.js';
import {loadToolPolicy} from './security-policy.js';

/** A transparent stdio MCP subprocess proxy. Not an enforcement boundary. */
export function proxyMcp({ configFile, server, database, debugStderr = false, cwd, policyFile }) {
  if (!configFile || !server) throw new Error('Proxy needs --config and --server');
  const configPath = resolve(configFile);
  const childConfig = getExecutableServer(configPath, server);
  const policy=loadToolPolicy(policyFile,server);
  const store = new GraphStore(database);
  const observer = new McpObserver(store, childConfig.name);
  let child;
  try {
    child = spawn(childConfig.command, childConfig.args, {
      // The wrapper inherits the MCP client's working directory. Do not switch
      // to the private snapshot directory created by `faraday install`.
      cwd: childConfig.cwd ? resolve(cwd || process.cwd(), childConfig.cwd) : (cwd || process.cwd()),
      env: { ...process.env, ...childConfig.env },
      stdio: ['pipe','pipe', debugStderr ? 'inherit' : 'ignore'],
      shell: false,
    });
  } catch (e) { store.close(); throw e; }
  // Nothing except the upstream MCP server is ever written to proxy stdout.
  child.stdin.on('error', () => { /* Downstream closed; exit is handled below. */ });
  if(policy)tapGuardedJsonLines(process.stdin,child.stdin,observer,policy,process.stdout);
  else tapJsonLines(process.stdin, child.stdin, observer, 'client_to_server');
  tapJsonLines(child.stdout, process.stdout, observer, 'server_to_client');
  child.on('error', () => {
    process.stderr.write('[FARADAY] MCP server could not be started\n');
    process.exitCode = 1;
  });
  child.on('exit', (code, signal) => {
    if (signal || code !== 0) {
      process.stderr.write('[FARADAY] MCP server exited abnormally\n');
      process.exitCode = 1;
    }
  });
  for (const sig of ['SIGTERM','SIGINT']) {
    process.on(sig, () => child.kill(sig));
  }
  return { child, store };
}
