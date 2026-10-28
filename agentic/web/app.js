const params=new URLSearchParams(location.search);
const key=params.get('key');
const $=(id)=>document.getElementById(id);
const NS='http://www.w3.org/2000/svg';
const SVG=(name,attrs={})=>{const e=document.createElementNS(NS,name);for(const [k,v] of Object.entries(attrs))e.setAttribute(k,String(v));return e;};
const text=(node,value)=>{node.textContent=value;return node;};
let lastGraph;
async function update(){
  try{
    const [g,e]=await Promise.all(['/api/graph','/api/events'].map(path=>fetch(path+'?key='+encodeURIComponent(key)).then(r=>{if(!r.ok)throw Error('API unavailable');return r.json();})));
    lastGraph=g;
    for(const type of ['client','server','tool']) $(type+'s').textContent=g.nodes.filter(n=>n.type===type).length;
    $('calls').textContent=g.stats.toolCalls;
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
