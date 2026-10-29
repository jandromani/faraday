import test from 'node:test';
import assert from 'node:assert/strict';
import {runBenchmarks,runSyntheticGatewayBenchmark} from '../lib/benchmarks.js';
test('E27 offline benchmark measures policy and replay p95/median',()=>{
  const x=runBenchmarks({iterations:15});assert.equal(x.format,'faraday-offline-microbenchmarks');
  assert.equal(x.percentileMethod,'nearest-rank');
  for(const v of Object.values(x.cases)){
    assert.equal(v.iterations,15);assert.equal(v.warmupIterations,15);assert.ok(Number.isFinite(v.medianMs));assert.ok(v.medianMs>=0);assert.ok(v.p95Ms>=v.medianMs);assert.ok(v.p99Ms>=v.p95Ms);assert.ok(v.maxMs>=v.p99Ms);
  }
});
test('E27 reject expensive or invalid benchmark configurations',()=>{
  assert.throws(()=>runBenchmarks({iterations:1}),/Iterations/);
  assert.throws(()=>runBenchmarks({iterations:100000000}),/Iterations/);
});
test('E27 bounded concurrent gateway benchmark reports latency, effects and a negative control',async()=>{
  const report=await runSyntheticGatewayBenchmark({requests:12,concurrency:3});
  assert.equal(report.successes,12);assert.equal(report.httpErrors,0);assert.equal(report.transportErrors,0);
  assert.equal(report.backendOperations,12);assert.equal(report.effectsMatchSuccesses,true);
  assert.equal(report.negativeControl.http,403);assert.equal(report.negativeControl.effects,0);assert.equal(report.negativeControl.falsePermits,0);
  assert.equal(report.latency.samples,12);assert.ok(report.latency.p50Ms>=0);assert.ok(report.latency.p95Ms>=report.latency.p50Ms);assert.ok(report.latency.p99Ms>=report.latency.p95Ms);
  assert.ok(report.throughputPerSecond>0);assert.ok(report.process.rssAfterBytes>0);assert.ok(report.process.cpuUserMs>=0);
});
test('E27 rejects unbounded concurrent benchmark configurations',async()=>{
  for(const options of [{requests:0},{requests:201},{requests:2,concurrency:3},{requests:20,concurrency:17},{requests:2.5}])
    await assert.rejects(runSyntheticGatewayBenchmark(options));
});
