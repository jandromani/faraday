const params=new URLSearchParams(location.search);
const key=params.get('key');
const $=(id)=>document.getElementById(id);
const NS='http://www.w3.org/2000/svg';
const SVG=(name,attrs={})=>{const e=document.createElementNS(NS,name);for(const [k,v] of Object.entries(attrs))e.setAttribute(k,String(v));return e;};
const text=(node,value)=>{node.textContent=value;return node;};
let lastGraph;
async function updateRecovery(){
  const summary=$('recovery-summary'),list=$('recovery-list');
  try{
    const response=await fetch('/api/recovery');if(!response.ok)throw Error('Recovery unavailable');
    const report=await response.json();list.replaceChildren();
    if(!report.configured){summary.textContent='No journal configured';return;}
    const counts=report.summary;
    summary.textContent=`${counts.uncertain} uncertain | ${counts.staleReserved} stale | ${counts.freshReserved} pending | ${counts.clockAnomalies} clock anomalies`;
    if(!report.operations.length){const empty=document.createElement('p');empty.className='event';empty.textContent='No pending or uncertain operations';list.append(empty);}
    for(const operation of report.operations.slice(0,100)){
      const row=document.createElement('div');row.className='event';
      const label=document.createElement('div');label.textContent=operation.id;
      const detail=document.createElement('small');detail.textContent=operation.operatorAction;label.append(detail);
      const state=document.createElement('span');state.className='outcome';state.textContent=operation.state;
      row.append(label,state);list.append(row);
    }
    if(report.operations.length>100){const notice=document.createElement('p');notice.className='event';notice.textContent=`Showing 100 of ${report.operations.length} operations`;list.append(notice);}
  }catch{summary.textContent='Recovery inspection unavailable';list.replaceChildren();}
}
async function update(){
  updateRecovery();
  try{
    const [g,e,contracts]=await Promise.all(['/api/graph','/api/events','/api/contracts'].map(path=>fetch(path).then(r=>{if(!r.ok)throw Error('API unavailable');return r.json();})));
    lastGraph=g;
    for(const type of ['client','server','tool']) $(type+'s').textContent=g.nodes.filter(n=>n.type===type).length;
    $('calls').textContent=g.stats.toolCalls;
    $('contracts').textContent=contracts.tools.length;
    const contractsList=$('contracts-list');contractsList.replaceChildren();
    if(!contracts.tools.length){const p=document.createElement('p');p.className='event';p.textContent='No contracts observed yet. Route MCP tools/list through the FARADAY proxy.';contractsList.append(p);}
    for(const c of contracts.tools.slice(0,100)){const entry=document.createElement('div');entry.className='event';
      const left=document.createElement('div');left.textContent=c.server+' / '+c.tool;
      const secondary=document.createElement('small');secondary.textContent='Input properties: '+Object.keys(c.inputSchema?.properties||{}).length+' · Potential clients: '+(c.potentialClients.join(', ')||'unknown');left.append(secondary);
      const badge=document.createElement('span');badge.className='outcome';badge.textContent=c.fingerprint.slice(0,10);entry.append(left,badge);contractsList.append(entry);}
    $('status').textContent='● LOCAL • OBSERVING';
    graph(g);
    const list=$('event-list');list.replaceChildren();
    if(!e.length){const p=document.createElement('p');p.className='event';p.textContent='No runtime events yet. Run FARADAY through the MCP proxy.';list.append(p);}
    for(const ev of e.slice(0,100)){
      const row=document.createElement('div');row.className='event';
      const a=document.createElement('div');text(a,ev.operation+(ev.tool?' · '+ev.tool:''));
      const small=document.createElement('small');text(small,ev.server+'  /  '+ev.direction+'  /  '+ev.ts);a.append(small);
      const b=document.createElement('span');b.className='outcome';text(b,ev.status||'·');
      row.append(a,b);list.append(row);
    }
  }catch(e){$('status').textContent='● LOCAL API ERROR';}
}
function graph(g){
  const svg=$('graph');svg.replaceChildren();
  const groups=['client','server','tool','transport'];
  const columns=new Map(groups.map((s,i)=>[s,i]));
  const ordered=g.nodes.slice().sort((a,b)=>(columns.get(a.type)??10)-(columns.get(b.type)??10)||a.label.localeCompare(b.label));
  const offsets=new Map(groups.map(s=>[s,0]));
  const coordinates=new Map();
  for(const n of ordered){const idx=offsets.get(n.type)||0;offsets.set(n.type,idx+1);coordinates.set(n.id,{x:25+(columns.get(n.type)||0)*245,y:55+idx*85});}
  const height=Math.max(390,...[...offsets.values()].map(n=>n*85+130));
  svg.setAttribute('viewBox',`0 0 985 ${height}`);
  svg.setAttribute('height',height);
  for(const e of g.edges){const a=coordinates.get(e.src),b=coordinates.get(e.dst);if(!a||!b)continue;
    const line=SVG('line',{x1:a.x+185,y1:a.y+20,x2:b.x,y2:b.y+20,class:'edge'});svg.append(line);
  }
  for(const n of ordered){const p=coordinates.get(n.id);const node=SVG('g',{class:'node '+n.type,transform:`translate(${p.x} ${p.y})`,tabindex:0,role:'button','aria-label':n.label});
    node.append(SVG('rect',{width:185,height:44,rx:9}));
    const label=SVG('text',{x:12,y:27});text(label,n.label.length>25?n.label.slice(0,22)+'…':n.label);node.append(label);
    const select=()=>{const related=g.edges.filter(e=>e.src===n.id||e.dst===n.id);
      $('details').textContent=`${n.type.toUpperCase()} • ${n.label}  |  ${related.length} relationships  |  last seen ${n.last_seen}`;};
    node.addEventListener('click',select);
    node.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();select();}});
    svg.append(node);
  }
}
$('refresh').addEventListener('click',update);update();setInterval(update,5000);
