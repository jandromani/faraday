# R6 — Real issuer token + signed Authority execution (CI proof)

This replaces the previous Keycloak **read-only** smoke with an explicit machine
identity mapping and a real HTTP synthetic effect. It does NOT provision human
delegation or production SSO.

## Trust boundary

- A disposable official Keycloak signs a client-credentials token with RS256 and
  exact MCP audience + execute scope; FARADAY validates pinned JWKS, issuer,
  expiration, authorized client ID (`azp`) and scope.
- An operator provisions `oauthClientAgentBindings: {'faraday-r5':
  'faraday://lab/finance'}`. No other signed OIDC client can invoke this agent.
  This mapping is **machine-to-agent administrative authorization**, not
  user impersonation, user OBO, or RFC token exchange.
- The gateway additionally requires a **separate signed, short-lived FARADAY
  execution proof and Authority capability** for the *same* agent and exact
  tool, resource, action and arguments. A Keycloak token by itself does not
  authorize execution.
- The backend independently validates its service credential and persists one
  synthetic operation, returning an independently signed attestation. The
  gateway signs a receipt that an independent verifier checks.
- Replay, tampered arguments, another Keycloak client and direct backend calls
  without service credentials must all fail while effect count stays one.

## Limits and future R6 gates

The CI gateway/backend are both loopback and use test-created service
credentials. The combined CI workflow now requires an official Vault dev-mode server,
installs a restricted **read-only AppRole** credential in the gateway, checks
that revocation prevents an operation before it is spent, and requires a fresh
scoped token to resume. This claim is valid only for a successful real GitHub
Actions run on the exact commit. The backend is still on loopback; there is
no network isolation between independent hosts. It
does not execute a real payment, nor an irreversible effect.

Before R6 enterprise acceptance: combine independent Vault token issuance and
revocation, actual workload identity, strict ingress/no-bypass, and trusted
backend effect counting within one campaign; test token revocation mid-flight,
secret rotation, receipt tampering and external evidence with recorded artifacts.
