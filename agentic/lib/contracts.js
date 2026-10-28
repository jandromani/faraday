import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { basename, dirname, resolve, join } from 'node:path';
import { safeLabel } from './discover.js';

// IMPORTANT: metadata only. Tool descriptions, defaults, enum literals, examples,
// argument values and arbitrary JSON Schema extensions are never persisted.
const TYPES = new Set(['null', 'boolean', 'object', 'array', 'number', 'integer', 'string']);
const KEYS = new Set(['type','properties','required','items','additionalProperties','oneOf','anyOf','allOf']);
const MAX_DEPTH = 8, MAX_PROPERTIES = 128, MAX_BRANCHES = 16;
const obj = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const ordered = o => Array.isArray(o) ? o.map(ordered) : obj(o) ? Object.fromEntries(Object.keys(o).sort().map(k => [k, ordered(o[k])])) : o;
export const canonical = o => JSON.stringify(ordered(o));
export const digest = o => createHash('sha256').update(canonical(o)).digest('hex');

export function normalizeSchema(schema, depth = 0) {
  if (!obj(schema)) return { kind: 'unknown' };
  if (depth >= MAX_DEPTH) return {kind:'truncated'};
  const shape = {kind:'schema'};
  if (typeof schema.type === 'string') shape.types = TYPES.has(schema.type) ? [schema.type] : [];
  else if (Array.isArray(schema.type)) shape.types = [...new Set(schema.type.filter(t => TYPES.has(t)))].sort();
  if (obj(schema.properties)) {
    const entries=Object.entries(schema.properties).slice(0, MAX_PROPERTIES);
    shape.properties=Object.fromEntries(entries.map(([key,value])=>[safeLabel(key),normalizeSchema(value,depth+1)]).sort(([a],[b])=>a.localeCompare(b)));
    if (Object.keys(schema.properties).length > MAX_PROPERTIES) shape.truncated = true;
  }
  if (Array.isArray(schema.required)) shape.required=[...new Set(schema.required.filter(x=>typeof x==='string').map(safeLabel))].sort().slice(0, MAX_PROPERTIES);
  if (Object.hasOwn(schema,'items')) shape.items=normalizeSchema(schema.items,depth+1);
  if (typeof schema.additionalProperties === 'boolean') shape.additionalProperties=schema.additionalProperties;
  else if (obj(schema.additionalProperties)) shape.additionalProperties=normalizeSchema(schema.additionalProperties,depth+1);
  for (const key of ['oneOf','anyOf','allOf']) if (Array.isArray(schema[key])) {
    shape[key]=schema[key].slice(0,MAX_BRANCHES).map(v=>normalizeSchema(v,depth+1));
    if (schema[key].length>MAX_BRANCHES) shape.truncated=true;
  }
  // Only marker, not value: non-modeled constraints need manual review.
  if (Object.keys(schema).some(k=>!KEYS.has(k))) shape.unmodeled=true;
  if (Object.hasOwn(schema,'$ref')) shape.unmodeled=true;
  return shape;
}

export function snapshotFromStore(store) {
  const graph=store.snapshot();
  const byId=new Map(graph.nodes.map(n=>[n.id,n]));
  const clientsByServer=new Map();
  for (const edge of graph.edges) if (edge.relation==='configured' && byId.get(edge.src)?.type==='client' && byId.get(edge.dst)?.type==='server') {
    const clients=clientsByServer.get(edge.dst)||new Set();
    clients.add(byId.get(edge.src).label);clientsByServer.set(edge.dst, clients);
  }
  return {
    format:'faraday-contract-snapshot', version:1, coverage:'observed-tools-list',
    tools:store.contracts().map(row=>({
      server:row.server, tool:row.tool, fingerprint:row.fingerprint,
      inputSchema:JSON.parse(row.input_schema), outputSchema:row.output_schema ? JSON.parse(row.output_schema) : null,
      potentialClients:[...(clientsByServer.get('server:'+row.server)||[])].sort(),
    })).sort((a,b)=>(a.server+'/'+a.tool).localeCompare(b.server+'/'+b.tool)),
  };
}

function validateSnapshot(snapshot) {
  if (!obj(snapshot) || snapshot.format!=='faraday-contract-snapshot' || snapshot.version!==1 || !Array.isArray(snapshot.tools) || snapshot.tools.length>5000) throw new Error('Invalid FARADAY snapshot');
  const ids=new Set();
  for (const tool of snapshot.tools) {
    if (!obj(tool)||typeof tool.server!=='string'||typeof tool.tool!=='string'||!obj(tool.inputSchema)||!Array.isArray(tool.potentialClients)||tool.potentialClients.some(x=>typeof x!=='string')) throw new Error('Invalid snapshot tool');
    const id=tool.server+'\u0000'+tool.tool;
    if (ids.has(id)) throw new Error('Duplicate tool in snapshot');ids.add(id);
  }
  return snapshot;
}
export function readSnapshot(path) {
  const content=readFileSync(path,'utf8');
  if (Buffer.byteLength(content)>10_000_000) throw new Error('Snapshot too large');
  return validateSnapshot(JSON.parse(content));
}
export function saveSnapshot(path, snapshot) {
  validateSnapshot(snapshot);
  mkdirSync(dirname(resolve(path)),{recursive:true,mode:0o700});
  writeFileSync(path,JSON.stringify(snapshot,null,2)+'\n',{encoding:'utf8',mode:0o600});
}
function reportChange(changes, severity, path, message) { changes.push({severity,path,message}); }
function diffShape(before,after,path,changes,mode='input',depth=0) {
  if (canonical(before)===canonical(after)) return;
  if (!obj(before)||!obj(after)||before.kind!=='schema'||after.kind!=='schema'||depth>MAX_DEPTH) {
    reportChange(changes,'review',path,'Unresolved or truncated schema changed');return;
  }
  const oldTypes=before.types||[],newTypes=after.types||[];
  if (canonical(oldTypes)!==canonical(newTypes)) {
    const widening=oldTypes.length && newTypes.length && oldTypes.every(t=>newTypes.includes(t));
    reportChange(changes,mode==='output'?'review':widening?'additive':'breaking',path+'.type','Accepted type set changed');
  }
  const bProps=before.properties||{},aProps=after.properties||{};
  for (const key of Object.keys(bProps)) {
    if (!Object.hasOwn(aProps,key)) reportChange(changes,mode==='output'?'review':'breaking',path+'.'+key,'Property removed');
    else diffShape(bProps[key],aProps[key],path+'.'+key,changes,mode,depth+1);
  }
  for (const key of Object.keys(aProps)) if (!Object.hasOwn(bProps,key)) reportChange(changes,mode==='output'?'review':(after.required||[]).includes(key)?'breaking':'additive',path+'.'+key,'Property added');
  const oldReq=new Set(before.required||[]),newReq=new Set(after.required||[]);
  for (const key of newReq) if (!oldReq.has(key)) reportChange(changes,mode==='output'?'review':'breaking',path+'.'+key,'New required property');
  for (const key of oldReq) if (!newReq.has(key)) reportChange(changes,mode==='output'?'review':'additive',path+'.'+key,'Required constraint removed');
  if (canonical(before.items)!==canonical(after.items)) diffShape(before.items,after.items,path+'[]',changes,mode,depth+1);
  if (canonical(before.additionalProperties)!==canonical(after.additionalProperties)) {
    const blocked=before.additionalProperties!==false&&after.additionalProperties===false;
    reportChange(changes,mode==='output'?'review':blocked?'breaking':'review',path+'.additionalProperties','Additional properties policy changed');
  }
  for (const key of ['allOf','oneOf','anyOf']) if (canonical(before[key])!==canonical(after[key])) reportChange(changes,'review',path+'.'+key,'Composition changed; manual review required');
  if (before.truncated||after.truncated) reportChange(changes,'review',path,'Truncated schema requires manual review');
  if (before.unmodeled!==after.unmodeled) reportChange(changes,'review',path,'Unmodeled constraints present/removed');
}
export function compareSnapshots(baseline,current) {
  validateSnapshot(baseline);validateSnapshot(current);
  const old=new Map(baseline.tools.map(t=>[t.server+'\u0000'+t.tool,t]));
  const next=new Map(current.tools.map(t=>[t.server+'\u0000'+t.tool,t]));
  const entries=[];
  for(const [id,from] of old) {
    const to=next.get(id), changes=[];
    if(!to) reportChange(changes,'breaking','tool','Observed tool removed from new snapshot');
    else {
      diffShape(from.inputSchema,to.inputSchema,'input',changes);
      if(canonical(from.outputSchema)!==canonical(to.outputSchema)) {
        if(from.outputSchema&&to.outputSchema) diffShape(from.outputSchema,to.outputSchema,'output',changes,'output');
        else reportChange(changes,'review','output','Output schema appeared or disappeared');
      }
    }
    if(changes.length) entries.push({server:from.server,tool:from.tool,potentialClients:[...new Set([...(from.potentialClients||[]),...(to?.potentialClients||[])])].sort(),changes});
  }
  for(const [id,tool] of next) if(!old.has(id)) entries.push({server:tool.server,tool:tool.tool,potentialClients:tool.potentialClients,changes:[{severity:'additive',path:'tool',message:'New observed tool'}]});
  entries.sort((a,b)=>(a.server+'/'+a.tool).localeCompare(b.server+'/'+b.tool));
  const summary={toolsBefore:baseline.tools.length,toolsAfter:current.tools.length,breaking:0,review:0,additive:0};
  for(const entry of entries)for(const c of entry.changes)summary[c.severity]++;
  return {format:'faraday-contract-diff',version:1,summary,entries,
    notes:['Potential clients are inferred from configuration, not proven runtime consumers.',
      'Only observed tools/list snapshots are compared; undiscovered tools are outside coverage.',
      'Descriptions, enum literals, defaults, patterns, numeric bounds and custom constraints are deliberately not captured. Absence of breaking findings is not a compatibility guarantee.']};
}

export function generateRegressionTests({baseline,current,outDir}) {
  const dir=resolve(outDir);
  if(!dir.includes('.faraday') && basename(dir)!=='faraday-regression') throw new Error('Generate tests in a dedicated .faraday or faraday-regression directory');
  const b=readSnapshot(baseline),c=readSnapshot(current);
  mkdirSync(dir,{recursive:true,mode:0o700});
  saveSnapshot(join(dir,'baseline.json'),b);saveSnapshot(join(dir,'current.json'),c);
  const source=`import { test } from 'node:test';\nimport assert from 'node:assert/strict';\nimport { readFileSync } from 'node:fs';\nimport { fileURLToPath } from 'node:url';\nimport { dirname, join } from 'node:path';\nimport { compareSnapshots } from '@faraday/agentic/contracts';\nconst here=dirname(fileURLToPath(import.meta.url));\nconst load=(name)=>JSON.parse(readFileSync(join(here,name),'utf8'));\ntest('FARADAY: no breaking changes to observed MCP tool contracts',()=>{\n const result=compareSnapshots(load('baseline.json'),load('current.json'));\n assert.equal(result.summary.breaking,0,JSON.stringify(result.entries,null,2));\n});\n`;
  writeFileSync(join(dir,'contracts.regression.test.mjs'),source,{mode:0o600});
  return {dir,breaking:compareSnapshots(b,c).summary.breaking,files:['baseline.json','current.json','contracts.regression.test.mjs']};
}
