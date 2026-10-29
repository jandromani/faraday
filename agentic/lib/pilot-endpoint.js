export function pilotBackendEndpoint(value,{allowInsecureBackend=false}={}){
  const endpoint=new URL(value);
  if(endpoint.pathname!=='/internal/execute'||endpoint.search||endpoint.hash||endpoint.username||endpoint.password||
     !['http:','https:'].includes(endpoint.protocol)||
     (endpoint.protocol==='http:'&&!['127.0.0.1','[::1]'].includes(endpoint.hostname)&&allowInsecureBackend!==true))
    throw Error('Fixed backend endpoint requires HTTPS or explicitly permitted insecure HTTP');
  return endpoint;
}