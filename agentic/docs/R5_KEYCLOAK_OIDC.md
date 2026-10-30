# R5 / R2: Official Keycloak HTTPS integration

Status: **real IdP development-mode integration, not R2 enterprise closure**.

This test uses an official version-pinned Keycloak server with a locally trusted
ephemeral TLS certificate on loopback. During CI it dynamically creates a realm,
two confidential OIDC clients and randomized secrets outside Git. One client
may access the FARADAY MCP resource; the other is intentionally denied even
though its JWT was signed by the same valid issuer.

## Explicit token profile

Default `PinnedOAuthResource` behavior remains RFC 9068:
- access JWT header `typ: at+jwt`
- exact issuer and single resource audience
- pinned public JWKS, no dynamic JWK fetching
- required client_id, exact tool scopes and expiry

For official Keycloak OIDC access JWTs only, the operator must explicitly set
`tokenProfile: 'keycloak-oidc'` with a nonempty
`allowedClientIds: ['faraday-r5']` allowlist. This permits `typ: JWT`, uses
Keycloak's signed `azp` to bind the allowed client, and requires the exact MCP
resource URL to be present in the signed audience set. Other clients, absent
resource audience, invalid signatures, expired tokens and missing scopes fail closed.
This exception must NOT be enabled for unrelated providers.

The CI run proves HTTPS discovery, Keycloak-issued client credentials access
JWTs, pinned JWKS RS256 signature, exact audience and scope enforcement, denied
second client, tampering, and FARADAY's local revocation overlay.

## Missing gates before R2 is accepted

- Real independent deployments for the IdP and gateway (not a local dev container);
- actual MCP tool execution with Keycloak subject cryptographically bound to
  the signed FARADAY agent capability and backend effect;
- IdP-issued delegation/token exchange policy with revocation propagation;
- mTLS/workload identity and periodic JWKS rotation, operator controls;
- isolated backend ingress, hostile-agent no-bypass under realistic permissions;
- independently reviewed receipts and attack evidence from one commit.

The test-only Keycloak client secrets, certificates and private key are ephemeral.
The image tag is a CI reference, not a production image/configuration recommendation.
Never accept the HTTP-only local synthetic OAuth tests as proof of this HTTPS path.
