/** Bounded, offline microbenchmarks. Measures a test environment, NOT production gateway latency. */
import {performance} from 'node:perf_hooks';
import {ToolPolicy} from './security-policy.js';
import {captureSynthetic,replaySynthetic} from './timemachine.js';
const percentile=(sorted,p)=>sorted[Math.max(0,Math.min(sorted.length-1,Math.ceil(sorted.length*p)-1))];
function measure(task,iterations){
  for(let i=0;i<Math.min(150,iterations);i++)task();
  const samples=[];
  for(let i=0;i<iterations;i++){
    const begin=performance.now();task();samples.push(performance.now()-begin);
  }
  samples.sort((a,b)=>a-b);
  return {iterations,medianMs:Number(percentile(samples,0.5).toFixed(4)),p95Ms:Number(percentile(samples,0.95).toFixed(4)),maxMs:Number(samples.at(-1).toFixed(4))};
}
export function runBenchmarks({iterations=200}={}){
  if(!Number.isSafeInteger(iterations)||iterations<10||iterations>2000)throw Error('Iterations must be 10–2000');
  const policy=new ToolPolicy({version:1,mode:'enforce',maxArgumentBytes:8192,allowedTools:{sandbox:['read_document']}},'sandbox');
  const req={jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'read_document',arguments:{id:'synthetic'}}};
  const trace=captureSynthetic({seed:42});
  return {format:'faraday-offline-microbenchmarks',version:1,environment:{node:process.version,platform:process.platform,arch:process.arch,
    cpuCount:null},cases:{policyDecision:measure(()=>policy.decision(req),iterations),replay:measure(()=>replaySynthetic(trace),iterations)},
    limitations:['Single-process local microbenchmarks; NOT end-to-end gateway throughput.',
      'Timing depends on CPU contention, runtime, and warmup; do not interpret as an SLA.',
      'No external tools, models or network services invoked.']};
}
