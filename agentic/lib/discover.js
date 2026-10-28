import { readFileSync, realpathSync, existsSync } from 'node:fs';
import { resolve, relative, join, isAbsolute } from 'node:path';
import { homedir, platform } from 'node:os';
import { createHash } from 'node:crypto';

const PROJECT_CONFIGS = [
  ['claude-code', '.mcp.json'],
  ['cursor', '.cursor/mcp.json'],
  ['vscode', '.vscode/mcp.json'],
  ['project', 'mcp.json'],
];

export const safeLabel = (raw) => {
  const s = typeof raw === 'string' ? raw : '';
  return /^[a-zA-Z0-9][a-zA-Z0-9_.:@/-]{0,79}$/.test(s)
    && !/(?:sk-|api[_-]?key|token|secret|bearer)/i.test(s)
    ? s : `redacted-${createHash('sha256').update(s).digest('hex').slice(0,10)}`;
};

export function globalSources(home = homedir(), os = platform()) {
  const entries = [
    ['cursor-global', join(home, '.cursor/mcp.json')],
    ['copilot-global', join(home, '.copilot/mcp-config.json')],
    ['windsurf-global', join(home, '.codeium/windsurf/mcp_config.json')],
  ];
  if (os === 'darwin') entries.push(['claude-desktop', join(home, 'Library/Application Support/Claude/claude_desktop_config.json')]);
  else if (os === 'win32') entries.push(['claude-desktop', join(process.env.APPDATA || home, 'Claude/claude_desktop_config.json')]);
  else entries.push(['claude-desktop', join(process.env.XDG_CONFIG_HOME || join(home,'.config'), 'Claude/claude_desktop_config.json')]);
  return entries;
}

export function configServers(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('Expected MCP config object');
  const values = [];
  for (const key of ['mcpServers', 'servers']) {
    if (!Object.hasOwn(config, key)) continue;
    const servers = config[key];
    if (!servers || typeof servers !== 'object' || Array.isArray(servers)) throw new Error(`Invalid ${key}`);
    for (const [name, data] of Object.entries(servers)) {
      if (!data || typeof data !== 'object' || Array.isArray(data)) continue;
      const transport = (data.type === 'http' || data.type === 'streamable-http' || data.type === 'sse' ||
        (!data.command && typeof data.url === 'string')) ? (data.type === 'sse' ? 'sse' : 'http') : 'stdio';
      values.push({ name, data, transport });
    }
  }
  return values;
}

function isInside(root, file) {
  const rel = relative(root, file);
  return rel === '' || (rel !== '..' && !rel.startsWith('../') && !rel.startsWith('..\\') && !isAbsolute(rel));
}

export function readMcpConfig(file) {
  const st = readFileSync(file, 'utf8');
  if (st.length > 2_000_000) throw new Error('Config too large');
  return JSON.parse(st);
}

export function discover({ root = process.cwd(), includeGlobal = false, globalEntries = null } = {}) {
  const absoluteRoot = realpathSync(resolve(root));
  const sources = PROJECT_CONFIGS.map(([client, path]) => ({
    client, file: resolve(absoluteRoot, path), label: `workspace:${path}`, scoped: true,
  }));
  if (includeGlobal) {
    for (const [client, file] of globalEntries || globalSources()) {
      sources.push({ client, file, label: `global:${client}`, scoped: false });
    }
  }
  const inventory = [];
  const warnings = [];
  for (const src of sources) {
    if (!existsSync(src.file)) continue;
    try {
      // Do not follow workspace symlinks that escape the workspace tree.
      const actual = realpathSync(src.file);
      if (src.scoped && !isInside(absoluteRoot, actual)) {
        warnings.push(`${src.label}: skipped symlink outside workspace`);
        continue;
      }
      const servers = configServers(readMcpConfig(actual));
      for (const { name, transport } of servers) inventory.push({
        client: src.client, source: src.label, server: safeLabel(name), transport,
        // Raw command, argv, URL, env, headers and values are deliberately discarded.
      });
    } catch {
      warnings.push(`${src.label}: unreadable or invalid JSON/config`);
    }
  }
  return { root: absoluteRoot, sourcesChecked: sources.length,
    servers: inventory.sort((a,b) => (a.source+a.server).localeCompare(b.source+b.server)), warnings };
}

export function getExecutableServer(configFile, name) {
  const config = readMcpConfig(configFile);
  const selected = configServers(config).filter(s => s.name === name);
  if (selected.length !== 1) throw new Error('Server not found or ambiguous');
  const server = selected[0];
  if (server.transport !== 'stdio') throw new Error('Runtime proxy currently supports stdio MCP servers only');
  if (typeof server.data.command !== 'string' || !server.data.command ||
      !Array.isArray(server.data.args || []) || !(server.data.args || []).every(x => typeof x === 'string')) {
    throw new Error('Invalid stdio executable configuration');
  }
  if (server.data.env != null && (typeof server.data.env !== 'object' || Array.isArray(server.data.env) ||
      !Object.values(server.data.env).every(x => typeof x === 'string'))) {
    throw new Error('Invalid environment mapping');
  }
  return { name: safeLabel(name), command: server.data.command,
    args: server.data.args || [], env: server.data.env || {},
    cwd: typeof server.data.cwd === 'string' ? server.data.cwd : undefined };
}
