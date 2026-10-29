#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {DurableSyntheticStore,createDurableSyntheticBackend} from '../lib/pilot-backend.js';
import {createStrictSecretFileProvider} from '../lib/secret-file-provider.js';
import {createVaultKv2SecretProvider} from '../lib/vault-kv2-secret-provider.js';
const store=new DurableSyntheticStore(process.env.FARADAY_BACKEND_DB);
const vaultConfig=process.env.FARADAY_VAULT_KV2_CONFIG?JSON.parse(readFileSync(process.env.FARADAY_VAULT_KV2_CONFIG,'utf8')):null;
const server=createDurableSyntheticBackend({secretProvider:vaultConfig?createVaultKv2SecretProvider(vaultConfig):createStrictSecretFileProvider(process.env.FARADAY_BACKEND_SECRET_FILE),store,attestationPrivatePem:readFileSync(process.env.FARADAY_BACKEND_ATTESTATION_PRIVATE_FILE,'utf8')});
server.listen(Number(process.env.PORT||8099),'0.0.0.0',()=>console.log('FARADAY durable synthetic backend'));
const stop=()=>server.close(()=>{store.close();process.exit(0);});
process.on('SIGTERM',stop);process.on('SIGINT',stop);
