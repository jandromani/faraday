#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {createSyntheticBackend} from '../lib/authority-gateway.js';
const secret=readFileSync(process.env.FARADAY_BACKEND_SECRET_FILE,'utf8').trim();
const port=Number(process.env.PORT??8099);
const server=createSyntheticBackend({secret});
server.listen(port,'0.0.0.0',()=>console.log('FARADAY synthetic backend running'));
