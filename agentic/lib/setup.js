import { readFileSync, writeFileSync, existsSync, lstatSync, mkdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { discover } from './discover.js';
import { GraphStore } from './store.js';

const gitignoreMatches = text => text.split(/\r?\n/).some(line => {
  const v=line.trim();return v==='.faraday/'||v==='.faraday'||v==='/.faraday/'||v==='/.faraday';
});
function requireProject(root){
  const p=resolve(root);
  if(!existsSync(p)||!lstatSync(p).isDirectory()||lstatSync(p).isSymbolicLink())throw new Error('Workspace root must be an existing ordinary directory');
  return p;
}
export function doctor({root=process.cwd(),includeGlobal=false}={}){
  const path=requireProject(root),report=discover({root:path,includeGlobal});
  const gitignore=join(path,'.gitignore');
  let ignored=false;
  if(existsSync(gitignore)) {
    if(lstatSync(gitignore).isSymbolicLink()||!lstatSync(gitignore).isFile()) throw Error('Unsafe .gitignore; inspect manually');
    ignored=gitignoreMatches(readFileSync(gitignore,'utf8'));
  }
  const nodeOk=Number(process.versions.node.split('.')[0])>=22 &&
    (Number(process.versions.node.split('.')[0])!==22 || Number(process.versions.node.split('.')[1])>=16);
  const checks=[
    {name:'node',ok:nodeOk,detail:nodeOk?'Node.js supports node:sqlite':'Requires Node.js 22.16 or newer'},
    {name:'gitignore',ok:ignored,detail:ignored?'Private .faraday/ ignored':'Add .faraday/ to .gitignore before storing metadata'},
    {name:'mcp-configs',ok:report.servers.length>0,detail:`${report.servers.length} compatible server configurations discovered (not verified reachable)`},
    {name:'config-parse',ok:report.warnings.length===0,detail:`${report.warnings.length} config warnings`},
    {name:'stdio',ok:report.servers.some(e=>e.transport==='stdio'||e.transport==='http'),detail:'Local proxy or HTTP bridge available for stdio and Streamable HTTP MCP servers'},
  ];
  return {root:path,readOnly:true,checks,servers:report.servers,warnings:report.warnings,
    ready:checks.filter(c=>c.name==='node'||c.name==='gitignore'||c.name==='config-parse').every(c=>c.ok),
    note:'Discovery never contacts servers, executes tools or modifies MCP configs.'};
}
export function initialize({root=process.cwd(),dryRun=false}={}){
  const path=requireProject(root),ignore=join(path,'.gitignore'),directory=join(path,'.faraday');
  const current=existsSync(ignore)?readFileSync(ignore,'utf8'):'';
  if(existsSync(ignore)&&(lstatSync(ignore).isSymbolicLink()||!lstatSync(ignore).isFile())) throw Error('Unsafe .gitignore');
  if(existsSync(directory)&&(lstatSync(directory).isSymbolicLink()||!lstatSync(directory).isDirectory())) throw Error('Unsafe .faraday directory');
  const writeIgnore=!gitignoreMatches(current);
  const report=discover({root:path});
  const actions=[];
  if(writeIgnore)actions.push('Append .faraday/ to .gitignore');
  actions.push(`Index ${report.servers.length} configured MCP servers (no network requests)`);
  if(dryRun)return {root:path,dryRun:true,actions,warnings:report.warnings};
  // Protect against a partially configured workspace: ensure gitignore first.
  if(writeIgnore)writeFileSync(ignore,current + (current&&!current.endsWith('\n')?'\n':'') + '.faraday/\n',{flag:'w',encoding:'utf8'});
  mkdirSync(directory,{recursive:true,mode:0o700});
  const db=join(directory,'graph.sqlite');
  const store=new GraphStore(db);
  try{store.inventory(report.servers);}finally{store.close();}
  return {root:path,dryRun:false,db,actions,warnings:report.warnings,
    next:['faraday doctor --root '+path,'faraday serve --db '+db]};
}
