#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {DurableSyntheticStore,createDurableSyntheticBackend} from '../lib/pilot-backend.js';
const store=new DurableSyntheticStore(process.env.FARADAY_BACKEND_DB);
const server=createDurableSyntheticBackend({secret:readFileSync(process.env.FARADAY_BACKEND_SECRET_FILE,'utf8').trim(),store,attestationPrivatePem:readFileSync(process.env.FARADAY_BACKEND_ATTESTATION_PRIVATE_FILE,'utf8')});
server.listen(Number(process.env.PORT||8099),'0.0.0.0',()=>console.log('FARADAY durable synthetic backend'));
const stop=()=>server.close(()=>{store.close();process.exit(0);});
process.on('SIGTERM',stop);process.on('SIGINT',stop);
