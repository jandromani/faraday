/** Bounded, offline microbenchmarks. Measures a test environment, NOT production gateway latency. */
import {performance} from 'node:perf_hooks';
import {ToolPolicy} from './security-policy.js';
import {captureSynthetic,replaySynthetic} from './timemachine.js';
import {SyntheticAgentHarness} from './workflow-e2e.js';
import {ARGS} from './authority-fixture.js';
const percentile=(sorted,p)=>sorted[Math.max(0,Math.min(sorted.length-1,Math.ceil(sorted.length*p)-1))];
function measure(task,iterations){
  const warmupIterations=Math.min(150,iterations);
  for(let i=0;i<warmupIterations;i++)task();
  const samples=[];
  for(let i=0;i<iterations;i++){
    const begin=performance.now();task();samples.push(performance.now()-begin);
  }
  samples.sort((a,b)=>a-b);
  return {iterations,warmupIterations,medianMs:percentile(samples,0.5),p95Ms:percentile(samples,0.95),p99Ms:percentile(samples,0.99),maxMs:samples.at(-1)};
}
export function runBenchmarks({iterations=200}={}){
  if(!Number.isSafeInteger(iterations)||iterations<10||iterations>2000)throw Error('Iterations must be 10–2000');
  const policy=new ToolPolicy({version:1,mode:'enforce',maxArgumentBytes:8192,allowedTools:{sandbox:['read_document']}},'sandbox');
  const req={jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'read_document',arguments:{id:'synthetic'}}};
  const trace=captureSynthetic({seed:42});
  return {format:'faraday-offline-microbenchmarks',version:1,environment:{node:process.version,platform:process.platform,arch:process.arch,
    cpuCount:null},percentileMethod:'nearest-rank',cases:{policyDecision:measure(()=>policy.decision(req),iterations),replay:measure(()=>replaySynthetic(trace),iterations)},
    limitations:['Single-process local microbenchmarks; NOT end-to-end gateway throughput.',
      'Timing depends on CPU contention, runtime, and warmup; do not interpret as an SLA.',
      'No external tools, models or network services invoked.']};
}
export async function runSyntheticGatewayBenchmark({requests=20,concurrency=2}={}){
  if(!Number.isSafeInteger(requests)||requests<1||requests>200)throw Error('Requests must be 1..200');
  if(!Number.isSafeInteger(concurrency)||concurrency<1||concurrency>16||concurrency>requests)throw Error('Concurrency must be 1..16 and no more than requests');
  const harness=await SyntheticAgentHarness.create();
  try{
    const probe=harness.issue(),beforeProbe=harness.store.count();
    const denied=await harness.call({...probe,args:{...ARGS,amount_cents:ARGS.amount_cents+1}});
    const probeEffects=harness.store.count()-beforeProbe;
    const falsePermits=denied.status===200||probeEffects!==0?1:0;
    const probeErrors=denied.status!==403&&falsePermits===0?1:0;
    const credentials=Array.from({length:requests},()=>harness.issue());
    const samples=[],rssBefore=process.memoryUsage().rss,cpuBefore=process.cpuUsage(),start=performance.now();
    let next=0,successes=0,httpErrors=0,transportErrors=0;
    async function worker(){
      while(next<credentials.length){
        const index=next++,begin=performance.now();
        try{const response=await harness.call(credentials[index]);samples.push(performance.now()-begin);
          if(response.status===200)successes++;else httpErrors++;
        }catch{transportErrors++;}
      }
    }
    await Promise.all(Array.from({length:concurrency},()=>worker()));
    const elapsedMs=performance.now()-start,cpu=process.cpuUsage(cpuBefore),rssAfter=process.memoryUsage().rss;
    samples.sort((left,right)=>left-right);
    const latency=samples.length?{samples:samples.length,p50Ms:percentile(samples,0.5),p95Ms:percentile(samples,0.95),p99Ms:percentile(samples,0.99)}:null;
    const effects=harness.store.count()-beforeProbe-probeEffects;
    return {format:'faraday-synthetic-gateway-benchmark',version:1,environment:{node:process.version,platform:process.platform,arch:process.arch},
      requests,concurrency,elapsedMs,throughputPerSecond:successes/(elapsedMs/1000),latency,
      successes,httpErrors,transportErrors,backendOperations:effects,effectsMatchSuccesses:effects===successes,
      negativeControl:{http:denied.status,effects:probeEffects,falsePermits,errors:probeErrors},
      process:{cpuUserMs:cpu.user/1000,cpuSystemMs:cpu.system/1000,rssBeforeBytes:rssBefore,rssAfterBytes:rssAfter},
      limitations:['Loopback synthetic client, gateway and backend share one process; not an external benchmark or isolation test.',
        'Credentials are issued before timing; latency includes response parsing but not credential issuance or receipt verification.',
        'CPU and RSS cover the entire process, not per-service usage or peak memory. No baseline gateway or operational cost measured.']};
  }finally{await harness.close();}
}
