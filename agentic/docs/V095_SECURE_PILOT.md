# FARADAY v0.95 — Secure Pilot

**Status: isolated, synthetic developer pilot. Not certified for financial transactions, production secrets, enterprise identity, or arbitrary MCP servers.**

## What v0.95 adds

1. **Authenticated MCP tool path:** protected `POST /mcp`, a limited subset of `initialize`, `tools/list`, `tools/call`. A trusted harness injects a signed capability and agent proof-of-possession through HTTP headers; the LLM does not get access to private keys. The gateway confirms exact signed tool arguments, scope, audience, policy, expiry and nonce.
2. **Fixed downstream:** the gateway calls exactly one configured backend host/path and injects a gateway-only service credential. The agent cannot select the destination. No real payment APIs exist in this code.
3. **Durable synthetic idempotency:** SQLite in the backend atomically records operation IDs and request hashes; duplicate identical IDs return a cached synthetic status, whereas a conflicting hash is rejected. Persistence across backend process restarts is tested. This is not a real-world exactly-once transaction.
4. **Crash-recovery journal:** a separate gateway SQLite journal marks `reserved`, `simulated`, `upstream-uncertain` or `upstream-rejected`. Ambiguous upstream results are not retried automatically. Operator reconciliation is required for uncertain outcomes.
5. **Verifiable receipts:** Ed25519 gateway signatures bind tool, agent, resource, action, argument digest, policy rule, status and timestamp. `faraday pilot verify --receipt FILE --public-key PEM` validates offline. Receipts attest **what the gateway observed**; they do not independently prove that the backend completed a real business operation.
6. **Container-isolated demo:** a dummy agent belongs only to `agent_zone`; the synthetic backend belongs only to `backend_private`; the gateway is dual-homed, and no backend host port is published. A CI step attempts a direct backend call, unauthorized MCP call, valid signed call and replay.
7. **No paid inference:** tests use native Node.js cryptography and SQLite; free AI advice remains optional and completely outside authorization.

## Quickstart

```sh
cd agentic
npm test
npm run pilot
npm run pilot:eval    # 100 cryptographic MCP scenarios, no external calls
npm run pilot:docker  # requires Docker Compose
```

The reference demo returns `stolen=403`, `allowed=200`, `replay=403`, `direct=401` and a valid signed receipt. `pilot:docker` requires a running Docker daemon and a non-root POSIX user. It creates a separate temporary Compose project and tests the disposable network topology.

The Docker test now includes a separate synthetic rogue tool without agent or backend credentials. It attempts direct connections to the backend and to an outside fixture by IPv4 address, checks selected secret paths, read-only mounts, UID, capabilities and `no-new-privileges`, and sends anonymous and forged requests to the gateway. A separate control reaches the outside fixture; a successful authorized call confirms the backend is up. These checks cover only this Docker topology and selected paths, not arbitrary tools, host access, host compromise, all egress destinations or alternative credentials. The updated topology has not been run in the current environment because the Docker daemon is unavailable.

### MCP subset

- Version labels tested: `2026-07-28` and `2025-11-25`.
- `initialize`, `tools/list`, `tools/call` only; JSON responses, no SSE subscriptions, no MRTR, no OAuth.
- On 2026 tool calls, the endpoint requires `MCP-Protocol-Version`, matching request `_meta`, `Mcp-Method` and `Mcp-Name`.
- The capability and execution proof are passed in **FARADAY-specific headers** by a trusted runtime, not typed into the LLM conversation.
- The tool fixture is fixed to `pay_invoice`, `invoice:demo`, `pay`, recipient `supplier_demo`, EUR, max 20000 cents. No general-purpose MCP forwarding/enforcement is claimed.
- Browser origins are rejected unless added to the trusted origin list; the API is intended for an isolated test network, not exposed to the internet.

This is **not** a conformant general-purpose MCP 2026 gateway, nor a standard OAuth 2.1 protected resource. See [MCP Streamable HTTP](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/transports/streamable-http.mdx).

## Operational guarantees and gaps

| Security property | Demonstrated | Remaining gap |
| --- | --- | --- |
| Signed caller proof, signed capability | In native Node.js cryptographic tests | Identity of running workload is not independently attested; static pinned keys |
| No replay of a spent capability | Single-node atomic SQLite ledger | No distributed/cluster revocation and recovery |
| No direct backend access from dummy-agent container | Docker Compose network test | Does not protect against host admin, Docker socket, side channels, alternative routes, direct SaaS endpoints |
| Durable request idempotency in synthetic backend | SQLite survives restart, exact request hash bound to ID | Real payments and side-effecting third-party tools need their own idempotency/transaction semantics |
| Verifiable receipt | Signatures verified offline; tampering detected | Signature by gateway only, not independent backend attestation; receipt signing key in gateway process |
| Unknown outcomes | Recorded, no automated retry | Manual reconciliation needed; durable distributed outbox not implemented |
| Zero-cost synthetic verification | Offline, no model billing | Infrastructure/test runner costs not included |

## Trust and custody

- Issuer private key lives outside Docker gateway; gateway receives issuer public key only.
- Agent private key lives only inside the dummy-agent container, never gateway/backend.
- Backend service credential is shared only between gateway and backend, never agent.
- Gateway receipt private key lives in the gateway (development-only limitation). Production needs independent signing/KMS-backed custody and signed backend acknowledgments.
- Docker volumes are synthetic and ephemeral; in a real deployment, persistent encrypted storage, workload identity and read-only root filesystem are needed.

## Optional Vault KV v2 reader

The pilot gateway can read the backend credential from a Vault KV v2-compatible endpoint instead of `backendSecretFile`. Configure `vaultBackendSecret` in the trusted pilot JSON, for example:

```json
{"baseUrl":"https://vault.example","mount":"secret","secretPath":"gateway/backend","field":"backend_credential","tokenFile":"/run/secrets/vault-token"}
```

The two credential sources are mutually exclusive. The gateway reads the token file and fetches the latest KV v2 value for each tool request, without a stale fallback, and performs the final Authority, approval, OAuth and sentinel checks after this wait. A failed lookup returns 503 before spending the capability. HTTPS is required except when `allowLoopbackHttp` is explicitly `true` for local tests; redirects are rejected. The token and value must be available to the gateway process. Pilot entrypoints reject non-regular private files and insecure POSIX modes; Windows ACLs and path races are not verified.

Tests use a local HTTP Vault-shaped fixture, not a Vault server. KV v2 stores a static value: updating it changes the gateway's next read, but the backend must also be rotated separately. This does not issue or revoke backend credentials, synchronize rotation, manage Vault tokens, isolate tenants, or provide KMS or Vault authentication lifecycle. Lookup occurs before the proof's signature is verified, so unauthenticated callers can cause Vault requests; operators need network access controls and rate limits. A malicious configured Vault endpoint, compromised process, host, or writable secret path can disclose credentials. Do not treat this preview as a production secrets broker.

## Future acceptance gates before 1.0

- MCP authorization compliant with actual provider resource audiences, complete transport conformance and OAuth protected resource metadata.
- Workload attestation (SPIFFE/SPIRE or enterprise workload OIDC), dynamic revocation, key rotation and policy approvals.
- An isolated hardened executor with direct network/credential paths provably closed in each target deployment.
- Signed receipts corroborated by tool/backend and durable reconciliation for uncertain outcomes.
- Fuzzing, 1000-case adversarial corpus with clearly labeled gaps, code review, external penetration test, multi-client compatibility, latency/SLO analysis.

Security baselines: [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10), [OWASP Agent Control Standard 2026](https://genai.owasp.org/2026/09/01/owasp-genai-security-project-unveils-2026-top-10-for-llm-applications-new-agent-control-standard-and-sponsors-as-community-tops-30000-members/).
