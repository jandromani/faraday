/** Local OAuth revocation boundary for the MCP resource server.
 * Operator-provisioned SQLite file; raw subjects, clients and jtis are never stored.
 * This is NOT an enterprise-wide distributed revocation service.
 */
import {createHash,randomBytes} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {existsSync,lstatSync,mkdirSync,chmodSync} from 'node:fs';
import {dirname,resolve} from 'node:path';

const kinds=new Set(['jti','subject','client']);
function identifier(kind,value){
  if(!kinds.has(kind)||typeof value!=='string'||value.length<1||value.length>512||/[\u0000-\u001f\u007f]/.test(value))throw Error('invalid-revocation-identifier');
}
export class LocalOAuthRevocations {
  constructor(path,{create=false}={}){
    if(typeof path!=='string'||!path)throw Error('revocation-path-required');
    const location=resolve(path);
    if(create)mkdirSync(dirname(location),{recursive:true,mode:0o700});
    if(!create&&!existsSync(location))throw Error('revocation-ledger-missing');
    if(existsSync(location)){
      const info=lstatSync(location);
      if(!info.isFile()||info.isSymbolicLink())throw Error('unsafe-revocation-ledger');
    }
    this.db=new DatabaseSync(location,{readOnly:!create});
    if(create){
      this.db.exec("PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY CHECK(id=1),salt TEXT NOT NULL); CREATE TABLE IF NOT EXISTS revocations (kind TEXT NOT NULL,fingerprint TEXT NOT NULL,reason TEXT NOT NULL,at_ms INTEGER NOT NULL,PRIMARY KEY(kind,fingerprint));");
      this.db.prepare('INSERT OR IGNORE INTO metadata(id,salt) VALUES (1,?)').run(randomBytes(32).toString('hex'));
      if(process.platform!=='win32')chmodSync(location,0o600);
    }
    const meta=this.db.prepare('SELECT salt FROM metadata WHERE id=1').get();
    if(!meta||!/^([a-f0-9]{64})$/.test(meta.salt))throw Error('invalid-revocation-ledger');
    this.salt=meta.salt;
    this.lookup=this.db.prepare('SELECT 1 AS revoked FROM revocations WHERE kind=? AND fingerprint=? LIMIT 1');
    if(create)this.write=this.db.prepare('INSERT OR IGNORE INTO revocations(kind,fingerprint,reason,at_ms) VALUES (?,?,?,?)');
  }
  fingerprint(kind,value){
    identifier(kind,value);
    return createHash('sha256').update(`FARADAY-REVOCATION-V1\0${this.salt}\0${kind}\0${value}`).digest('hex');
  }
  revoke(kind,value,{reason='operator',at=Date.now()}={}){
    if(!this.write)throw Error('revocation-ledger-read-only');
    if(typeof reason!=='string'||!/^[a-zA-Z0-9._-]{1,80}$/.test(reason)||!Number.isSafeInteger(at)||at<0)throw Error('invalid-revocation-event');
    const fp=this.fingerprint(kind,value);
    // Irreversible within this API: this ledger does not support reinstatement.
    const result=this.write.run(kind,fp,reason,at);
    return {kind,fingerprint:fp,inserted:result.changes===1};
  }
  isRevoked({jti,subject,clientId}){
    if(typeof jti!=='string'||!jti)throw Error('jti-required-when-revocation-enabled');
    for(const [kind,value] of [['jti',jti],['subject',subject],['client',clientId]]){
      const fp=this.fingerprint(kind,value);
      if(this.lookup.get(kind,fp))return true;
    }
    return false;
  }
  close(){this.db.close();}
}
