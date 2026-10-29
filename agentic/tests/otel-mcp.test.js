import {test} from 'node:test';import assert from 'node:assert/strict';
import {toSafeOtelMcpSpan} from '../lib/otel-mcp.js';
test('MCP/GenAI span contains no prompts, raw tool names or inputs',()=>{
 const s=toSafeOtelMcpSpan({method:'tools/call',tool:'my_sensitive_tool',decision:'deny',durationMs:12});
 assert.equal(s.attributes['mcp.method.name'],'tools/call');
 assert.equal(s.attributes['gen_ai.operation.name'],'execute_tool');
 assert.match(s.attributes['faraday.tool.fingerprint'],/^[a-f0-9]{16}$/);
 assert.doesNotMatch(JSON.stringify(s),/my_sensitive_tool|arguments|result|bearer-token/);
 assert.equal(s.traceId.length,32);
});
test('Reject unsafe methods, invalid decisions, leaked tool attribution and malformed trace ids',()=>{
 assert.throws(()=>toSafeOtelMcpSpan({method:'unsafe/method',decision:'allow'}));
 assert.throws(()=>toSafeOtelMcpSpan({method:'tools/list',decision:'allow',tool:'foo'}));
 assert.throws(()=>toSafeOtelMcpSpan({method:'tools/call',decision:'pass'}));
 assert.throws(()=>toSafeOtelMcpSpan({method:'tools/call',decision:'allow',traceId:'abc'}));
});
