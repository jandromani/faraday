# FARADAY v0.99.3 — OAuth 2.1 MCP resource boundary

**Release class:** Experimental Secure Developer Preview — NOT enterprise certification or full OAuth 2.1 / MCP conformance.

## New, validated scope (E06, E09, E10, E11, E24–E27)

- **HTTP MCP /mcp**: modern 2026-07-28 `server/discover`, `tools/list`, `tools/call` with structured modern result envelopes, plus a **limited** legacy 2025-11-25 `initialize` and tool calls. JSON response only; no SSE, task subscriptions, MRTR, prompts or resources.
- **Optional OAuth resource-server enforcement**: accepts externally issued `at+jwt` bearer access tokens, signed EdDSA Ed25519 or RSA RS256 and validated against **pinned public JWKs**. Validates issuer, exact resource audience, expiry, issued-at, optional not-before, client identity, required per-action scope and signature. No symmetric, unsigned or arbitrary algorithm fallback. No dynamic JWKS network requests.
- **RFC 9728 protected resource metadata** served at `/.well-known/oauth-protected-resource/mcp` and root alias; RFC 6750 Bearer challenge and `401 invalid_token`/`403 insufficient_scope`.
- **Two independent gates**: OAuth JWT AND FARADAY capability signed by the registered Ed25519 agent. The token `sub` must equal the signed FARADAY agent identity. Token scope is derived from the **JSON-RPC BODY**, never `Mcp-Method` headers. Modern header/body mismatches are rejected before any side effect. Upstream backend never receives the OAuth token.
- **Tests**: 11 new OAuth HTTP/security integration tests, 200 repeatable synthetic token cases, existing Graph/Authority suite and CI matrix (Linux/macOS/Windows, Node 22/24).

## Operator configuration

Add an `oauthResource` stanza to the **existing trusted** `FARADAY_PILOT_CONFIG`. OAuth is **disabled** unless configured, for backwards compatibility with the offline lab. Never expose that legacy mode on the public Internet.

```json
{
  "oauthResource": {
    "issuer": "https://identity.example.org",
    "authorizationServers": ["https://identity.example.org"],
    "resource": "https://mcp.example.org/mcp",
    "publicJwksFile": "/run/faraday/oauth-public-jwks.json",
    "readScope": "mcp:tools:read",
    "executeScope": "mcp:tools:execute"
  }
}
```

The public JWKS file contains `{"keys":[{"kid":"stable-id","kty":"OKP","crv":"Ed25519","x":"public-base64url","alg":"EdDSA"}]}`. NO private JWK members. Rotate the signed public key set by controlled configuration deployment. The configured `resource` must be the externally visible **HTTPS** MCP URL, not the internal container URL. The issuer of the token must be trusted explicitly. Token `sub` must match the FARADAY agent ID (for example `faraday://lab/finance` in the synthetic fixture).

TLS termination, OAuth identity-provider login, authorization-code PKCE/CIMD client flows, KMS, key rotation automation, rate limits, non-bypass network controls and workload attestation are **external or not implemented**. This module is a **resource server verifier**, not an OAuth authorization server.

## How to reproduce

```bash
cd agentic
npm run oauth:test
npm run oauth:eval
npm run test:all
```

The 200 evals are synthetic local token verification cases, not 200 independent attacks against a remote service. Microbenchmark median/p95 values are local CPU figures, **not gateway network latency SLOs**. Do not use the synthetic `pay_invoice` tool to claim real payment handling.

Protocol references: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization and https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http and https://modelcontextprotocol.io/specification/2026-07-28/server/discover
