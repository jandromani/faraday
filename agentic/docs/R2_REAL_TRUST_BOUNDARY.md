# R2 — Real Trust Boundary (E09–E14)
Status: **implementation in progress / NOT ACCEPTED**. R1's pending runner and ruleset requirements are not waived.

## Acceptance contract
R2 requires a **real HashiCorp Vault KVv2**, a **real HTTPS OIDC/OAuth IdP** and a network-isolated MCP gateway. Do not put Vault/IdP tokens or private signing keys in Git, artifacts, logs or agent mounts.

The actual deployment must demonstrate:
1. Valid scoped agent identity can traverse MCP gateway to backend and produces a verifiable signed receipt.
2. Invalid and revoked identity is rejected, including stale/replayed credentials.
3. Revoked Vault credentials cease to authorize new calls; no cached credential can silently extend authority.
4. A hostile agent cannot route to backend directly and cannot read gateway/backend secret volumes.
5. Tampering with the receipt, signature, replay state or policy must fail closed.
6. The full suite runs against the same commit, with captured network evidence and artifact SHA-256 hashes.

## Evidence schema
`lib/r2-evidence-gate.js` and `tests/r2-evidence-gate.test.js` implement a **manifest completeness and consistency gate**, not the live infrastructure. It intentionally requires ten named live scenarios, tied to the same commit and independently hashed artifacts under `artifacts/r2/`. The issuer must use HTTPS. The CI collector must *actually compare every digest against artifact bytes* before setting `artifactDigestsVerified=true`. Never allow a user-submitted manifest to assert this field without independent verification.

## Blocking conditions
- Docker boundary checks or mocked OAuth/Vault tests alone cannot satisfy R2.
- Do not provision a production IdP/Vault using placeholder credentials.
- No passing label without successful live CI evidence, genuine credential revocation, backend network denial and independently checked receipts.
- Developer Preview only; no external certification or production isolation claim.
