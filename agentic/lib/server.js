import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { GraphStore } from './store.js';
import { snapshotFromStore } from './contracts.js';
import {inspectRecovery} from './recovery-inspector.js';

const STATIC_ROOT = join(dirname(fileURLToPath(import.meta.url)), '../web');
const ASSETS = new Map([
  ['/', ['index.html','text/html; charset=utf-8']],
  ['/app.js', ['app.js','text/javascript; charset=utf-8']],
  ['/style.css', ['style.css','text/css; charset=utf-8']],
]);
function constantTimeEquals(a, b) {
  if (typeof a !== 'string') return false;
  const left=Buffer.from(a),right=Buffer.from(b);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left,right);
}

/** Serve metadata-only read-only UI on loopback with an ephemeral access key. */
export async function serveGraph({database, port = 0, onReady = () => {}, journalPath = null}) {
  if(journalPath!==null&&(typeof journalPath!=='string'||!journalPath))throw Error('Invalid recovery journal path');
  const journal=journalPath===null?null:resolve(journalPath);
  if(journal)inspectRecovery({path:journal});
  const store = new GraphStore(database);
  const token = randomBytes(24).toString('hex');
  const cookieName = 'faraday_session';
  const web = createServer((req, res) => {
    const u = new URL(req.url, 'http://127.0.0.1');
    const headers = {
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'",
    };
    if (req.method !== 'GET') { res.writeHead(405, headers).end(); return; }
    const incomingCookie = (req.headers.cookie || '').split(';').map(s=>s.trim()).find(s=>s.startsWith(cookieName+'='));
    const cookieToken = incomingCookie?.slice((cookieName+'=').length);
    const validQuery = constantTimeEquals(u.searchParams.get('key'),token);
    const validCookie = constantTimeEquals(cookieToken,token);
    if (req.headers.host !== `127.0.0.1:${web.address().port}`) {
      res.writeHead(403, headers).end('Forbidden'); return;
    }
    if (validQuery && u.pathname === '/') {
      res.writeHead(302,{...headers,'Set-Cookie':`${cookieName}=${token}; HttpOnly; SameSite=Strict; Path=/`,'Location':'/'}).end();
      return;
    }
    if (!validCookie) {
      res.writeHead(403, headers).end('Forbidden'); return;
    }
    if (u.pathname === '/api/recovery') {
      try {
        const data=journal?{configured:true,...inspectRecovery({path:journal})}:{configured:false};
        res.writeHead(200,{...headers,'Content-Type':'application/json; charset=utf-8'}).end(JSON.stringify(data));
      } catch {res.writeHead(503,headers).end('Recovery inspection unavailable');}
      return;
    }
    if (u.pathname === '/api/graph' || u.pathname === '/api/events' || u.pathname === '/api/contracts') {
      try {
        const data = u.pathname === '/api/graph' ? store.snapshot() : (u.pathname === '/api/events' ? store.events(200) : snapshotFromStore(store));
        res.writeHead(200, {...headers,'Content-Type':'application/json; charset=utf-8'})
          .end(JSON.stringify(data));
      } catch {
        res.writeHead(503, headers).end('Graph unavailable');
      }
      return;
    }
    const found = ASSETS.get(u.pathname);
    if (!found) { res.writeHead(404, headers).end(); return; }
    res.writeHead(200, {...headers,'Content-Type':found[1]}).end(readFileSync(join(STATIC_ROOT,found[0])));
  });
  await new Promise((resolve,reject) => web.once('error',reject).listen(port,'127.0.0.1',resolve));
  const actualPort = web.address().port;
  onReady(`http://127.0.0.1:${actualPort}/?key=${token}`);
  web.on('close',() => store.close());
  return { server:web,port:actualPort,token };
}
