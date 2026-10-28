import test from 'node:test';
import assert from 'node:assert/strict';
import {runBenchmarks} from '../lib/benchmarks.js';
test('E27 offline benchmark measures policy and replay p95/median',()=>{
  const x=runBenchmarks({iterations:15});assert.equal(x.format,'faraday-offline-microbenchmarks');
  for(const v of Object.values(x.cases)){
    assert.equal(v.iterations,15);assert.ok(Number.isFinite(v.medianMs));assert.ok(v.p95Ms>=v.medianMs);assert.ok(v.maxMs>=v.p95Ms);
  }
});
test('E27 reject expensive or invalid benchmark configurations',()=>{
  assert.throws(()=>runBenchmarks({iterations:1}),/Iterations/);
  assert.throws(()=>runBenchmarks({iterations:100000000}),/Iterations/);
});
