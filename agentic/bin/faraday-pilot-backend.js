#!/usr/bin/env node
import {readKeyFile} from '../lib/authority.js';
import {DurableSyntheticStore,createDurableSyntheticBackend} from '../lib/pilot-backend.js';
const secret=readKeyFile(process.env.FARADAY_BACKEND_SECRET_FILE,{privateKey:true}).trim();
const attestationPrivatePem=readKeyFile(process.env.FARADAY_BACKEND_ATTESTATION_PRIVATE_FILE,{privateKey:true});
const store=new DurableSyntheticStore(process.env.FARADAY_BACKEND_DB);
const server=createDurableSyntheticBackend({secret,store,attestationPrivatePem});
server.listen(Number(process.env.PORT||8099),'0.0.0.0',()=>console.log('FARADAY durable synthetic backend'));
const stop=()=>server.close(()=>{store.close();process.exit(0);});
process.on('SIGTERM',stop);process.on('SIGINT',stop);
