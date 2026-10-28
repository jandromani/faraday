/** Static compatibility inventory, not external MCP conformance certification. */
import {discover} from './discover.js';
export const PROTOCOL_PROFILE=Object.freeze({
 current:'2026-07-28',legacy:['2025-03-26','2025-06-18','2025-11-25'],
 transports:['stdio','streamable-http'],verifiedVia:'local synthetic fixtures only',
 notes:['2026-07-28 removes sessions and initialization; older versions can require them.',
 'The FARADAY bridge does not implement every MRTR/extension feature.',
 'Static configuration discovery does not prove connectivity or conformance.']});
export function compatibilityReport({root,includeGlobal=false}={}){
 const d=discover({root,includeGlobal});
 const servers=d.servers.map(s=>({client:s.client,server:s.server,source:s.source,transport:s.transport,
 eligibleForBridge:s.transport==='stdio'||s.transport==='http',
 observed:false,conformance:'untested',warning:s.transport==='sse'?'Legacy SSE cannot be bridged by FARADAY':null}));
 return {format:'faraday-compatibility',version:1,protocol:PROTOCOL_PROFILE,servers,
 warnings:d.warnings,summary:{configured:servers.length,eligible:servers.filter(s=>s.eligibleForBridge).length,verifiedLive:0},
 note:'Static scan never executes tools and never proves compatibility.'};
}
