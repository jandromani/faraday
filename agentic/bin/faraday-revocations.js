#!/usr/bin/env node
/** Local operator-only OAuth revocations. Secure file permissions are the operator's responsibility. */
import {LocalOAuthRevocations} from '../lib/oauth-revocations.js';
const options={};
for(let i=2;i<process.argv.length;i++){
  const arg=process.argv[i];
  if(arg.startsWith('--')&&i+1<process.argv.length)options[arg.slice(2)]=process.argv[++i];
  else if(!options.action)options.action=arg;
  else throw Error('unexpected-argument');
}
if(!options.db||!['init','revoke'].includes(options.action))throw Error('usage: node bin/faraday-revocations.js <init|revoke> --db FILE [--kind jti|subject|client --value ID]');
const ledger=new LocalOAuthRevocations(options.db,{create:true});
try{
  if(options.action==='init')console.log(JSON.stringify({status:'initialized',storage:'local-sqlite'}));
  else{
    if(!['jti','subject','client'].includes(options.kind)||!options.value)throw Error('kind-and-value-required');
    if(options.action==='revoke')console.log(JSON.stringify({status:'recorded',...ledger.revoke(options.kind,options.value)}));

  }
}finally{ledger.close();}
