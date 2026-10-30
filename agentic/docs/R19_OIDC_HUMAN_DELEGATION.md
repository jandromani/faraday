# R19 — Verified Keycloak user -> signed delegation -> protected MCP effect

R19 extends the existing R6 real issuer run, **without converting a machine
client token into a fictitious user identity**.

- An official Keycloak test realm issues a **user access JWT** via the
  intentionally CI-only password grant to a randomly credentialed test user.
- The pinned OAuth resource validates the issuer, actual RS256 signature,
  resource audience, allowed client, scopes and expiry. FARADAY
  exposes the cryptographically verified token expiry to a trusted operator.
- The operator approves the exact issuer/subject/client and signs a short
  Ed25519 delegation root bound to the hash of issuer+subject and the
  exact tool/resource/action/maximum amount. The grant cannot live longer
  than the authenticated JWT.
- A registered agent may issue a cryptographically verifiable narrower
  grant for another agent; the verifier rejects widened amounts, cycles,
  spliced parents and revoked users.
- A separate opt-in gateway `delegationVerifier` requires a valid user JWT,
  valid delegated chain, **plus** the ordinary signed FARADAY capability and
  execution proof before a synthetic protected MCP backend effect.
  Revocation is re-checked on every protected execution.
- The real Keycloak/Vault/Authority CI verifies an approved user can execute
  once, a machine token or an unbound bearer cannot impersonate the user,
  altered arguments and replays are denied, and removing user authorization
  blocks another effect.

## Trust and limitations

The Keycloak user is **test-only**. CI uses a password grant solely for a
disposable development realm: production MUST use a reviewed authorization
code + PKCE/consent or brokered identity integration, not passwords collected
by an agent. The operator callback is trusted policy: it must verify that
a principal is a human account that consented and is authorized for the
requested resource; never infer human status from `preferred_username`,
email, or a service account's name.

This proves provider-issued user JWT binding and an independent signed
delegation chain in CI. It does **not** prove OAuth Token Exchange/OBO,
production user consent, tenant isolation, workload mTLS, multi-agent remote
tool execution across hosts, or independent penetration testing.
The optional enforcement is not enabled for every FARADAY gateway by default.
No real customer, payment or production identity is involved.
