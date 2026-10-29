# ADR-002 — Buy or reuse a mature gateway data plane

**Decision:** don't reimplement general TLS, load balancing, retries, timeouts and HTTP traffic management. Keep FARADAY's deterministic pilot gateway until an external integration proves that Authority's mandatory boundary is maintained. Evaluate **agentgateway first** (MCP-native), with **Envoy Gateway ext_authz as a fallback/reference**.

| Decision criterion | agentgateway | Envoy ext_authz | FARADAY pilot |
|---|---|---|---|
| Native MCP routing | Yes | Needs MCP-specific service | Partial prototype |
| TLS, load balancing, rate limits | Available | Available | Do not extend |
| External authorization | Supported | Supported, HTTP/gRPC | In-process |
| FARADAY Ed25519 authority and receipts | Needs adapter and tests | Needs adapter and tests | Existing synthetic tests |
| FARADAY verified non-bypass | Not tested | Not tested | Docker synthetic topology |

`lib/gateway-policy-port.js` defines an **optional fail-closed** metadata-only external decision filter. The synthetic MCP pilot can opt in for `tools/call` using `externalPolicy: {authorize, timeoutMs}`; the filter does not enforce policy on discovery or `tools/list`. This is an in-process callback, not an agentgateway or Envoy integration. The callback receives only the method and hashes of the claimed agent and resource, not credentials, arguments or tool outputs. These claims are unverified when sent and a raw fingerprint is NOT anonymization against dictionary attacks. Deployments must secure any external transport themselves.

The filter is consulted before the capability is spent. Denial, invalid responses, errors and timeout prevent execution; an allow cannot replace subsequent Authority signature, identity, scope, replay and policy checks. Approvals, OAuth and emergency stop are rechecked after the wait. This ordering avoids relying on stale authorization after an external wait, but does not make the pilot a mandatory network boundary.

**Go/no-go tests before integration:** (1) policy service down/timeout means deny; (2) deny bad JWT-capability identity combinations; (3) block direct backend access; (4) prevent header/body privilege confusion; (5) prevent authorization route-cache or rewrite bypass; (6) preserve two separate signed receipts. The gateway and server must be network-isolated; an external authz ALLOW response alone never proves non-bypass.

Sources:
- https://agentgateway.dev/docs/standalone/latest/documentation/about/introduction/
- https://agentgateway.dev/docs/standalone/latest/documentation/configuration/security/external-authz/
- https://gateway.envoyproxy.io/latest/tasks/security/ext-auth/
- https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter

**Outcome today:** architecture comparison and an opt-in pilot filter tested locally; no external gateway deployment or integration certification.
