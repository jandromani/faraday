# FARADAY v0.99.6 — Vault KV v2 and no-bypass reference deployment

**Scope:** Secure Developer Preview. This is not a general zero-trust certification, production Vault IAM or independent penetration test.

## E11/E13 — Mandatory gateway reference topology

Docker Compose defines agent_zone (dummy agent, rogue agent, gateway) and an internal backend_private zone (backend, gateway). No agent receives the backend credential. The rogue Docker agent must fail to reach backend directly, then fail on anonymous or forged tool calls at the gateway.

The CI smoke evaluates the effective Compose JSON and rejects insecure network connections, exposed privileged containers, leaked secret mounts, disabled read-only root or missing resource limits. The proof applies ONLY to this reference Docker topology.

## E12 — Vault KV v2 secret adapter

The optional provider reads GET /v1/{mount}/data/{path} with a strictly permissioned token file, rejecting redirects, unencrypted remote Vault URLs, invalid JSON and excess response size. No stale credential fallback on provider failure.

Gateway operator config may contain vaultKv2BackendSecret (baseUrl, mount, secretPath, field, tokenFile); the backend independently accepts FARADAY_VAULT_KV2_CONFIG. Dev mode permits loopback HTTP only if explicitly opted in; remote Vault requires HTTPS.

The integration tests use a disposable HTTP mock. GitHub CI additionally runs an official HashiCorp Vault v1.20.4 dev container, testing read, rotate and revoke. This still does not implement Vault workload identity or lease renewal.

## Limitations

No third-party audit, no production isolation guarantee, no universal bypass prevention, no workload attestation, no Vault service in production, no KMS key custodians. All backend tool effects remain synthetic.
