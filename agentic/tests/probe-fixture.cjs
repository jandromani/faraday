// Strict stdio fake MCP server. Fixture has no access to tools outside synthetic calls.
const {createInterface}=require('node:readline');
const era=process.argv[2]||'modern';let initialized=false;
const toolName='read_only_fixture';
let i=0;
createInterface({input:process.stdin}).on('line',l=>{
  let m;try{m=JSON.parse(l)}catch{return;}
  if(!m||m.jsonrpc!=='2.0'||!m.method||m.id==null)return;
  let result,error;
  if(m.method==='server/discover'){
    if(era==='modern')result={resultType:'complete',supportedVersions:['2026-07-28'],capabilities:{tools:{}},_meta:{'io.modelcontextprotocol/serverInfo':{name:'fixture',version:'1'}}};
    else error={code:-32601,message:'Method not found'};
  }else if(m.method==='initialize' && era==='legacy'){
    result={protocolVersion:'2025-11-25',capabilities:{tools:{}},serverInfo:{name:'fixture',version:'1'}};
    initialized=true;
  }else if(m.method==='tools/list' && (era==='modern'||initialized)){
    if(m.params?.cursor==='page2')result={tools:[{name:'second_page',annotations:{readOnlyHint:true},inputSchema:{type:'object'}}]};
    else result={tools:[{name:toolName,annotations:{readOnlyHint:true},inputSchema:{type:'object'}}],nextCursor:'page2'};
  }else if(m.method==='tools/call'){
    result={content:[{type:'text',text:'SENSITIVE_SECRET_DO_NOT_LEAK'}]};
  }else error={code:-32601,message:'Method not found'};
  process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,...(result?{result}:{error})})+'\n');
});
