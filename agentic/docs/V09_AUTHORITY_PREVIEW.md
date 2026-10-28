# FARADAY v0.9 — Authority Preview (synthetic only)

Status: **developer preview**, not a production security boundary. FARADAY cannot guarantee zero bypasses in arbitrary infrastructures.

## Design / trust boundaries

```
OFFLINE AUTHORITY (issuer private key) -> signed narrowly scoped capability
                                        |
DUMMY AGENT (agent private key) ---- signed action proof (capability fingerprint)
                                        |
                                        v
                              AUTHORITY GATEWAY
                issuer public key + trusted agent public key
                          resource-scoped policy
                        replay ledger (SQLite)
                                        |
                          fixed upstream + service key
                                        |
                             SYNTHETIC BACKEND
```

- The issuer signs a capability authorizing one exact `agent`, `tool`, `resource`, `action`, hashed arguments, policy rule and audience. TTL 1–300s. **Issuer private key stays outside the gateway** in the reference deployment.
- An agent must demonstrate possession of the pinned Ed25519 private key twice: signed issuance intent and a separate signed execution proof bound to the exact issued capability.
- The gateway rechecks current policy, key binding, expiry, audience, tool, action, resource, arguments and nonce before a downstream request. Capability and execution nonces are atomically consumed in one SQLite transaction.
- The backend accepts calls only with a gateway-owned service secret. Its synthetic invoice handler has its own minimal allowlist and idempotency check. **No real payments or external side effects.**
- Gateway HTTP `/execute` is **a proprietary synthetic preview API, not an MCP OAuth authorization endpoint**; MCP compliance and real workload attestation are not yet implemented for this gateway.

## Quick start

```bash
npm install -g ./faraday-agentic-0.9.0.tgz # if using the release bundle
faraday authority demo
faraday authority eval --limit 100 --out authority-report.json
```

Or from the repository:

```bash
cd agentic
npm test
npm run authority
npm run authority:eval
npm run lab:docker  # requires Docker + Docker Compose, performs isolated-network test
```

## Docker network-isolated test

`npm run lab:docker` performs these checks on synthetic containers:

1. **Agent-only zone**: the dummy agent belongs to `agent_zone`, with no backend network membership or backend secret mounted.
2. **Backend-only zone**: the synthetic tool backend belongs exclusively to `backend_private`, an isolated Docker bridge network. It does not publish a host port.
3. **Gateway dual-homed**: only the gateway is connected to both networks; it receives public issuer/agent keys and gateway-only backend credentials, **never issuer signing keys**.
4. **Adversarial checks**: a direct backend request from the agent fails, unauthenticated tool request is denied, properly signed request succeeds, reuse of same capability is denied.

**This proof applies only to the provided Docker network topology**. It does not prove containment against host-root users, privileged containers, Docker daemon access, compromised kernel/host, malicious gateway code, network configuration drift, direct internet egress, or a real production tool that is separately reachable. Tests should run in CI on each release.

## Tests and evaluations

- Existing v0.8 synthetic lab: 1,000 scenarios with unsupported capabilities explicitly marked `gap`, never counted as passes. Retained unchanged.
- New v0.9 crypto eval: 100 scenarios covering legitimate operations, stolen capabilities, argument substitution, capability replays and resource policy restrictions using real Ed25519 signatures and persistent SQLite ledger. Synthetic keys are ephemeral and never committed.
- Unit/integration checks: signature tampering, wrong identity, expiry, key rotation, replay, forged request, direct backend authentication, malformed request and policy limits.
- Docker Compose CI separately verifies the network isolation property (not runnable on hosts without Docker).

## Limitations before production

- **No real SPIFFE-SVID/OIDC attestation.** Pinned keys demonstrate possession of a key, not which executable/process controls it. Real issuer key custody requires KMS/HSM and independent service boundary.
- **No OAuth 2.1 MCP HTTP authorization.** Production services need protected resource metadata, access tokens bound to the exact resource audience and proper 401/403 semantics.
- **No universally mandatory gateway.** Existing `stdio`/HTTP adapters remain optional and directly accessible outside the protected Docker topology. Deployments must enforce credential separation and network policies explicitly.
- **No distributed replay protection.** SQLite single-node ledger; crashes after a spent capability can cause an incomplete action. Retrying must issue a new capability after operator-controlled reconciliation; never silently repeat high-impact calls.
- **No general-purpose JSON Schema validation:** the example policy uses exact fields plus recipient/currency/amount checks. Other tools need explicit validators and test cases.
- **No production multi-tenancy, sandbox or audit receipts.** Gateway writes bounded metadata to local graph only when configured; does not emit signed evidence of downstream execution.
- **No user-level rate limits or authenticated approval workflow.** Cannot treat the synthetic fixture as financial authorization.
- **Crypto choices:** Node.js native Ed25519; canonical JSON serialization deterministic within this prototype; a standardized interoperable serialization format and external cryptography review are required before a public trust protocol.

## Next milestones (v0.95/v1.0)

1. Real workload identity/SPIFFE attestation, OAuth/resource audience, dynamic revocation and key rotation.
2. Resource-specific policies for heterogeneous tools, independent policy service and human approval.
3. Dedicated network sandbox and secured production deployment with direct tool/network access blocked.
4. Distributed idempotency, durable failure recovery, signing and independent verification of execution receipts.
5. External penetration tests, SLSA/SBOM, broad client/server compatibility matrix, false-allow benchmark.

References:
- [MCP authorization security considerations 2026-07-28](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/authorization/security-considerations.mdx)
- [SPIFFE concepts](https://spiffe.io/docs/latest/spiffe/concepts/)
