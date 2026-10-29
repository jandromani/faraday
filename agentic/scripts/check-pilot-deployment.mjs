#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {validateReferenceBoundary} from '../lib/deployment-boundary.js';
if(!process.argv[2])throw Error('Pass path to docker compose config --format json');
const report=validateReferenceBoundary(JSON.parse(readFileSync(process.argv[2],'utf8')));
console.log(JSON.stringify({kind:'faraday-reference-deployment-boundary',result:'pass',...report}));
