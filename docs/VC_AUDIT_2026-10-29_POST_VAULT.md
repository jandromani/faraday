# FARADAY — VC audit checkpoint after AppRole and Docker hardening

**Date:** 2026-10-29  
**Source SHA reviewed:** `db500a2a3a206c4bb0929535f047a696134ba9b1`  
**Score (provisional, not a security certification): 59.0/100**  
**Previous provisional score:** 58.6/100  
**Enterprise epics independently closed:** 0/32

## What demonstrably changed
- PR #22 introduced an official Vault dev-mode **AppRole** smoke: the service token is minted separately from the root bootstrap credential, has a narrowly scoped read-only KVv2 policy, and tests denied alternate-secret reads, admin routes, secret writes, credential rotation, revocation and reissue. The real Vault container has **not run successfully in the current GitHub CI**.
- The Docker reference boundary validator now rejects explicit root UID/GID, `cap_add`, host namespace overrides, unexpected/unconfined `security_opt`, unauthorized bind mounts, and writable credential/application bind mounts. The fixed reference expects exactly the approved normalized Docker Compose mounts.
- R1 signed candidate publication is now gated on a **new official Vault AppRole job**, in addition to the pre-existing Docker adversarial and 3-OS MCP jobs. The manual workflow remains unexecuted successfully on the evaluated commit.
- A mock AppRole protocol run exercised eight intended controls; ten isolated pure-JavaScript boundary probes passed. These do **not** replace the official Vault image, Docker container attack, full Node regression or external review.

## VC phase scoring (same weighting as prior review)

| Phase | Earlier | Updated provisional | Weight |
|---|---:|---:|---:|
| F0 Foundations | 64.5 | 64.5 | 9% |
| F1 Plug & Use | 76.8 | 76.8 | 12% |
| F2 Trust Boundary | 62.3 | 63.7 | 24% |
| F3 Reliable Runtime | 60.4 | 60.4 | 14% |
| F4 Agent Intelligence | 63.3 | 63.3 | 6% |
| F5 Lab | 71.5 | 71.5 | 12% |
| F6 Product Engineering | 53.4 | 53.6 | 10% |
| F7 Enterprise & Launch | 18.7 | 19.1 | 13% |

Weighted result = **59.0/100** (rounded). The increase is small because real Vault identity, a no-bypass deployment, and attested releases are still not independently proven on the evaluated commit. The original enterprise scope is unchanged.

## Blocking external checks (observed at review)
1. Nine GitHub Actions workflows for the source SHA remained queued without a successful conclusion. This is a repository/account runner problem until proven otherwise, **not a test pass**. See issue #17 and Actions.
2. `master` was `protected=false` and repository ruleset count was zero. GitHub App lacks administrative write access; the repository owner must enable required checks and disallow force pushes.
3. GitHub releases remained empty, with no hosted attestation verified.
4. No real full OAuth IdP deployment, cross-tenant enterprise IAM, two-node fencing, RPO/RTO evidence, independent pentest or customer reference was verified.

## Next acceptance milestone
- Restore runners and obtain green `Security Tests`, `Vault and Network Trust Boundary`, `Architecture and Blocking Assurance`, `Live MCP Interoperability` and remaining workflows **on the same SHA**.
- Run `FARADAY R1 Release Assurance and Attested Candidate` manually, first with `publish_prerelease=false`; verify Docker, official Vault AppRole, 3 OS MCP, archive integrity and Sigstore provenance. Do not publish on red/queued gates.
- Turn on a mandatory `master` ruleset using exact completed GitHub check names.
- Independently run the real no-bypass network attack and record artifacts, source SHA and hashes.

**VC verdict:** credible technical hardening of E11–E13 and release assurance, still advanced Developer Preview. Not Secure Beta, not Enterprise-certified. Scores are analytical judgement, not measured percentages of attack prevention.
