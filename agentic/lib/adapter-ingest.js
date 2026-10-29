import {readFileSync, lstatSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {GraphStore, nodeId} from './store.js';

const FRAMEWORKS = new Set(['langgraph','crewai','openai-agents']);
const KINDS = new Set(['node_call','tool_call','agent_start','agent_end']);
const STATUSES = new Set(['started','ok','error','denied','unverified']);
const FIELDS = new Set(['version','framework','agent','tool','kind','status','elapsed_ms']);
const ID = /^id-[0-9a-f]{24}$/;

export function validateAdapterRecord(value) {
  if(!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !FIELDS.has(key)) ||
      Object.keys(value).length !== FIELDS.size)
    throw Error('Unsupported adapter record: metadata-only schema required');
  if(value.version !== 1 || !FRAMEWORKS.has(value.framework) ||
      typeof value.agent!=='string' || typeof value.tool!=='string' || !ID.test(value.agent) || !ID.test(value.tool) ||
      !KINDS.has(value.kind) || !STATUSES.has(value.status) ||
      !Number.isSafeInteger(value.elapsed_ms) || value.elapsed_ms < 0 || value.elapsed_ms > 3600000)
    throw Error('Unsupported adapter record value');
  return value;
}

export function ingestAdapterFile({file, db}) {
  const input = resolve(file);
  const info = lstatSync(input);
  if(!info.isFile() || info.isSymbolicLink() || info.size > 8*1024*1024)
    throw Error('Adapter log must be a regular file <=8MiB (no symlinks)');
  const bytes = readFileSync(input);
  if(bytes.byteLength > 8*1024*1024) throw Error('Adapter file changed during read');
  const digest = createHash('sha256').update(bytes).digest('hex');
  const lines = bytes.toString('utf8').split('\n').filter(Boolean);
  if(lines.length>10000) throw Error('Too many adapter events');
  const entries = lines.map(line => {
    if(Buffer.byteLength(line)>4096) throw Error('Overlong adapter event');
    return validateAdapterRecord(JSON.parse(line));
  });
  const store = new GraphStore(db);
  try {
    store.db.exec('CREATE TABLE IF NOT EXISTS adapter_imports (digest TEXT PRIMARY KEY, count INTEGER NOT NULL)');
    const prior=store.db.prepare('SELECT count FROM adapter_imports WHERE digest=?').get(digest);
    if(prior) return {imported:0,skipped:prior.count,sha256:digest};
    store.db.exec('BEGIN IMMEDIATE');
    try{
      for(const e of entries){
        const framework = nodeId('framework',e.framework);
        const agent=nodeId('agent',e.framework+'/'+e.agent);
        const tool=nodeId('tool',e.framework+'/'+e.tool);
        store.node(framework,'framework',e.framework);
        store.node(agent,'agent',e.agent);
        store.edge(framework,agent,'hosts');
        if(e.kind==='tool_call'||e.kind==='node_call'){
          store.node(tool,e.kind==='node_call'?'node':'tool',e.tool);
          const relation=e.status==='denied'?(e.kind==='node_call'?'denied_node':'denied_tool'):
            ['started','unverified'].includes(e.status)?(e.kind==='node_call'?'observes_node':'observes_tool'):
            (e.kind==='node_call'?'executes_node':'calls_tool');
          store.edge(agent,tool,relation);
        }
        const direction=e.status==='started'?'request':e.status==='denied'?'denied':e.status==='unverified'?'observed':'response';
        store.event({server:e.framework,direction,kind:e.kind,
          operation:e.status,tool:e.tool,status:e.status,latencyMs:e.elapsed_ms});
      }
      store.db.prepare('INSERT INTO adapter_imports(digest,count) VALUES (?,?)').run(digest,entries.length);
      store.db.exec('COMMIT');
    }catch(error){store.db.exec('ROLLBACK');throw error;}
    return {imported:entries.length,skipped:0,sha256:digest};
  }finally{store.close();}
}
