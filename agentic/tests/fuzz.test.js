/** Deterministic mutation corpus: bounded, not coverage-guided fuzzing. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fixture,AGENT,TOOL,RESOURCE,ACTION,ARGS} from '../lib/authority-fixture.js';
import {newIdentity} from '../lib/authority.js';
import {signApproval,verifyApprovals} from '../lib/approvals.js';
function rng(seed=42){let x=seed>>>0;return ()=>((x=(Math.imul(x,1664525)+1013904223)>>>0)/2**32);}
const chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
function mutate(s,r){const i=Math.floor(r()*s.length),current=s[i];let c=chars[Math.floor(r()*chars.length)];if(c===current)c=chars[(chars.indexOf(current)+1)%chars.length];return s.slice(0,i)+c+s.slice(i+1);}
test('320 mutated capabilities must not authorize operations',t=>{
 const root=mkdtempSync(join(tmpdir(),'faraday-fuzz-'));t.after(()=>rmSync(root,{recursive:true,force:true}));
 const f=fixture(root);t.after(f.close);const r=rng(20261028);
 for(let i=0;i<320;i++)assert.throws(()=>f.gate.authorize({capability:mutate(f.capability,r),proof:f.proof}),undefined,'mutation '+i);
 assert.equal(f.gate.authorize({capability:f.capability,proof:f.proof}).tool,TOOL);
});
test('320 mutated approval signatures must not give consent',()=>{
 const a=newIdentity(),b=newIdentity(),scope={capability:'capability-1234567890123456789',agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS};
 const approvals=[signApproval({...scope,approver:'a',privatePem:a.privatePem}),signApproval({...scope,approver:'b',privatePem:b.privatePem})];
 const keys={a:{publicPem:a.publicPem,role:'security'},b:{publicPem:b.publicPem,role:'finance'}},r=rng(95);
 for(let i=0;i<320;i++)assert.throws(()=>verifyApprovals({bundle:[{...approvals[0],signature:mutate(approvals[0].signature,r)},approvals[1]],approverKeys:keys,quorum:2,requiredRoles:['security','finance'],...scope}),undefined,'mutation '+i);
 assert.equal(verifyApprovals({bundle:approvals,approverKeys:keys,quorum:2,...scope}).approved,true);
});
test('120 signed approval scope mutations must fail closed',()=>{
 const a=newIdentity(),b=newIdentity(),scope={capability:'capability-1234567890123456789',agent:AGENT,tool:TOOL,resource:RESOURCE,action:ACTION,args:ARGS};
 const keys={a:a.publicPem,b:b.publicPem},bundle=[signApproval({...scope,approver:'a',privatePem:a.privatePem}),signApproval({...scope,approver:'b',privatePem:b.privatePem})];
 for(let n=1;n<=120;n++){const altered={...scope,args:{...ARGS,amount_cents:n*100}};if(altered.args.amount_cents===ARGS.amount_cents)continue;
  assert.throws(()=>verifyApprovals({bundle,approverKeys:keys,quorum:2,...altered}));}
});
