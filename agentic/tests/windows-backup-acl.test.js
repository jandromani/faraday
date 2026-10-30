import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {protectWindowsAcl,verifyWindowsAcl} from '../lib/windows-backup-acl.js';

test('Windows secures file ACL and verifies it before backup use',{skip:process.platform!=='win32'},t=>{
 const root=mkdtempSync(join(tmpdir(),'faraday-windows-acl-'));
 t.after(()=>rmSync(root,{recursive:true,force:true}));
 const file=join(root,'test-backup.json');
 writeFileSync(file,JSON.stringify({test:true}));
 assert.throws(()=>verifyWindowsAcl(file),/ACL protection is not verified/);
 protectWindowsAcl(file);
 assert.doesNotThrow(()=>verifyWindowsAcl(file));
});
