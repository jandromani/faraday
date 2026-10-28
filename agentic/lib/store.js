import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, chmodSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { safeLabel } from './discover.js';
import { normalizeSchema, digest, canonical } from './contracts.js';

const MAX_EVENTS = 4000;
const at = () => new Date().toISOString();
const stableId = (kind, value) => `${kind}:${value}`;
export const nodeId = stableId;

export class GraphStore {
  constructor(path) {
    this.path = resolve(path);
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(this.path, { timeout: 5000 });
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS nodes (
        id TEXT PRIMARY KEY, type TEXT NOT NULL, label TEXT NOT NULL,
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS edges (
        src TEXT NOT NULL, dst TEXT NOT NULL, relation TEXT NOT NULL,
        occurrences INTEGER NOT NULL DEFAULT 1,
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
        PRIMARY KEY(src, dst, relation));
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
        server TEXT NOT NULL, direction TEXT NOT NULL, kind TEXT NOT NULL,
        operation TEXT NOT NULL, tool TEXT, status TEXT, latency_ms INTEGER);
      CREATE TABLE IF NOT EXISTS contracts (
        server TEXT NOT NULL, tool TEXT NOT NULL,
        input_schema TEXT NOT NULL, output_schema TEXT, fingerprint TEXT NOT NULL,
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
        PRIMARY KEY(server,tool));`);
    if (existsSync(this.path)) chmodSync(this.path, 0o600);
    this.nodeStatement = this.db.prepare(`INSERT INTO nodes (id,type,label,first_seen,last_seen)
      VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen`);
    this.edgeStatement = this.db.prepare(`INSERT INTO edges(src,dst,relation,occurrences,first_seen,last_seen)
      VALUES (?,?,?,1,?,?) ON CONFLICT(src,dst,relation)
      DO UPDATE SET occurrences=occurrences+1,last_seen=excluded.last_seen`);
    this.eventStatement = this.db.prepare(`INSERT INTO events(ts,server,direction,kind,operation,tool,status,latency_ms)
      VALUES (?,?,?,?,?,?,?,?)`);
  }

  node(id, type, label) {
    const t = at();
    this.nodeStatement.run(id, type, safeLabel(label), t, t);
  }
  edge(src, dst, relation) {
    const t = at();
    this.edgeStatement.run(src, dst, relation, t, t);
  }
  inventory(serverEntries) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (const e of serverEntries) {
        const client = stableId('client', safeLabel(e.client));
        const server = stableId('server', safeLabel(e.server));
        const transport = stableId('transport', safeLabel(e.transport));
        this.node(client, 'client', e.client);
        this.node(server, 'server', e.server);
        this.node(transport, 'transport', e.transport);
        this.edge(client, server, 'configured');
        this.edge(server, transport, 'uses_transport');
      }
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
  }
  observedServer(server) {
    const name = safeLabel(server);
    this.node(stableId('server', name), 'server', name);
    this.node('client:observed', 'client', 'observed');
    this.edge('client:observed', stableId('server', name), 'observed');
  }
  tool(server, rawName, relation = 'exposes') {
    const name = safeLabel(rawName);
    const owner = stableId('server', safeLabel(server));
    const tool = stableId('tool', safeLabel(server) + '/' + name);
    this.node(owner, 'server', server);
    this.node(tool, 'tool', name);
    this.edge(owner, tool, relation);
    return name;
  }
  contract(server, tool, inputSchema, outputSchema = null) {
    const who=safeLabel(server),name=safeLabel(tool);
    const input=normalizeSchema(inputSchema), output=outputSchema===null?null:normalizeSchema(outputSchema);
    const fingerprint=digest({input,output}),timestamp=at();
    this.tool(who,name);
    this.db.prepare(`INSERT INTO contracts(server,tool,input_schema,output_schema,fingerprint,first_seen,last_seen)
      VALUES(?,?,?,?,?,?,?) ON CONFLICT(server,tool) DO UPDATE SET
      input_schema=excluded.input_schema,output_schema=excluded.output_schema,
      fingerprint=excluded.fingerprint,last_seen=excluded.last_seen`).run(
        who,name,canonical(input),output===null?null:canonical(output),fingerprint,timestamp,timestamp);
    return fingerprint;
  }
  replaceContracts(server,tools) {
    const who=safeLabel(server);
    if (!Array.isArray(tools) || tools.length>2000) throw new Error('Invalid complete tools/list');
    this.db.exec('BEGIN IMMEDIATE');
    try {
      // Only a complete tools/list replaces the current tool contract snapshot.
      // History of nodes/edges/events remains independent from active contracts.
      this.db.prepare('DELETE FROM contracts WHERE server=?').run(who);
      for(const tool of tools) if(tool&&typeof tool.name==='string')
        this.contract(who,tool.name,tool.inputSchema,tool.outputSchema??null);
      this.db.exec('COMMIT');
    } catch(error) {this.db.exec('ROLLBACK');throw error;}
  }
  contracts() {return this.db.prepare('SELECT * FROM contracts ORDER BY server,tool').all();}
  event({server, direction, kind, operation, tool = null, status = null, latencyMs = null}) {
    const normalized = {
      server: safeLabel(server), direction: safeLabel(direction),
      kind: safeLabel(kind), operation: safeLabel(operation),
      tool: tool === null ? null : safeLabel(tool),
      status: status === null ? null : safeLabel(status),
      latencyMs: Number.isSafeInteger(latencyMs) && latencyMs >= 0 ? latencyMs : null,
    };
    this.eventStatement.run(at(), normalized.server, normalized.direction, normalized.kind,
      normalized.operation, normalized.tool, normalized.status, normalized.latencyMs);
    // Bounded local history; graph accumulates aggregates independently.
    this.db.prepare('DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0) - ? FROM events)').run(MAX_EVENTS);
  }
  snapshot() {
    return {
      nodes: this.db.prepare('SELECT * FROM nodes ORDER BY type,label').all(),
      edges: this.db.prepare('SELECT * FROM edges ORDER BY src,dst,relation').all(),
      stats: {
        nodes: this.db.prepare('SELECT COUNT(*) AS n FROM nodes').get().n,
        edges: this.db.prepare('SELECT COUNT(*) AS n FROM edges').get().n,
        events: this.db.prepare('SELECT COUNT(*) AS n FROM events').get().n,
        toolCalls: this.db.prepare("SELECT COUNT(*) AS n FROM events WHERE kind='tool_call' AND direction='response'").get().n,
        contracts: this.db.prepare('SELECT COUNT(*) AS n FROM contracts').get().n,
      },
    };
  }
  events(limit=100) {
    return this.db.prepare('SELECT * FROM events ORDER BY id DESC LIMIT ?').all(Math.max(1, Math.min(500, limit)));
  }
  close() { this.db.close(); }
}

export function toMermaid(graph) {
  const ids = new Map(graph.nodes.map((n,i)=>[n.id, 'n'+i]));
  const lines = ['flowchart LR'];
  for (const n of graph.nodes) {
    // Labels are sanitized before storage; escape again for output format.
    const label = n.label.replace(/["<>\\]/g, '_');
    lines.push(`  ${ids.get(n.id)}["${label} (${n.type})"]`);
  }
  for (const e of graph.edges) if (ids.has(e.src) && ids.has(e.dst)) {
    lines.push(`  ${ids.get(e.src)} -->|${e.relation}| ${ids.get(e.dst)}`);
  }
  return lines.join('\n')+'\n';
}
