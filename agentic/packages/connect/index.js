/** FARADAY Connect public migration boundary v1. Existing lib imports remain supported. */
export {discover,getExecutableServer,readMcpConfig,configServers} from '../../lib/discover.js';
export {installProxy,uninstallProxy} from '../../lib/install.js';
export {probeStdio} from '../../lib/mcp-live-probe.js';
export {validateAdapterRecord,ingestAdapterFile} from '../../lib/adapter-ingest.js';
export const CONNECT_API_VERSION='1.0.0-preview';
