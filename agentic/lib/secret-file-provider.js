/** Operator-managed backend credential file reader.
 * Reads a bounded 0600 regular file for every request, enabling credential rotation
 * without reopening client configurations. This is NOT a KMS or Vault client.
 */
import {lstatSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
export function createStrictSecretFileProvider(path,{minLength=32,maxLength=4096}={}){
 if(typeof path!=='string'||!path||!Number.isSafeInteger(minLength)||minLength<16||!Number.isSafeInteger(maxLength)||maxLength>8192||maxLength<minLength)throw Error('invalid-secret-file-configuration');
 const location=resolve(path);
 return function readBackendCredential(){
   const stat=lstatSync(location);
   if(!stat.isFile()||stat.isSymbolicLink()||stat.size>maxLength+2)throw Error('unsafe-secret-file');
   if(process.platform!=='win32' && (stat.mode&0o077)!==0)throw Error('secret-file-permissions');
   const buffer=readFileSync(location);
   try{
     const value=buffer.toString('utf8').trim();
     if(value.length<minLength||value.length>maxLength||!/^[A-Za-z0-9_+=./:-]+$/.test(value))throw Error('invalid-backend-credential');
     return value;
   }finally{buffer.fill(0);}
 };
}
