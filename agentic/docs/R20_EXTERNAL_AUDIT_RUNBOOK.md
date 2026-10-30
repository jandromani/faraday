# FARADAY R20 — External auditor reproducibility kit

**Status: ready for third-party review; NO reviewer has signed and NO independent pilot has been verified.**

## Scope and immutable inputs
1. Select an exact GitHub release **tag + commit SHA**, never `master` as an unpinned reference.
2. Verify the three release assets (tarball, manifest, SPDX inventory) by
   SHA-256 and `gh attestation verify <tarball> --repo jandromani/faraday`.
3. Record runner OS, Node version, GitHub Actions job URL, UTC time and
   reference digest, **not** raw credentials or identifiable host logs.
4. Confirm version-specific risk statements in `SECURITY.md` and
   `docs/R9_VC_AUDIT_2026-10-30.md`; an internal score is NOT a certification.

## Minimum independent attack matrix
| Boundary | Adversarial change | Pass condition |
|---|---|---|
| Keycloak/OIDC | wrong issuer, JWKS, audience, client, expiry, signed scope | No MCP protected effect |
| Delegation | wrong user or client, revoked subject, widened scope, spliced child chain | No receipt/effect |
| Authority | invalid proof, changed tool args, repeated capability | No second effect |
| Vault | revoked read AppRole, forbidden path, expired grant | No backend service secret |
| PostgreSQL | executor attempts promote, controller attempts effect, stale epoch | DB refuses |
| Split-brain | disconnect worker A from PostgreSQL, promote B, reconnect A | A's old epoch denied |
| Recovery | database unavailable after request, delayed result, retry | Unknown outcome reconciled; no blind repeat |
| Supply chain | repacked archive, mismatched SPDX/manifest/commit | Verification refuses release |
| Multi-tenant | foreign tenant/agent key, cross-project receipt substitution | Denied, independently documented |

Auditor must create **their own tests**, not simply reproduce existing GitHub
Actions logs; the internal tests are useful baselines only.

## Reproduction in isolated test environment
- Review release hashes and fetch read-only source at exact SHA.
- Execute R1, R12, R13, R14, R15, R18 in disposable infrastructure.
- For R18, use isolated Docker hosts/bridges and inspect each node's
  lease epoch and persisted PostgreSQL ledger count.
- Reproduce at least one negative case on a separate test codebase or tool.
- Attach a **redacted** proof with source SHA, command reference, expected
  result, observed result, sample count and limitation.
- Never run `pay_invoice` against a real financial system. All effects in
  these labs are synthetic.
- At least one true externally managed link fault or node crash should be
  executed outside the GitHub-hosted runner to assess production topology.

## Sign-off and acceptance
Use five independent installation scorecards in
`agentic/docs/R10_SCORECARD_TEMPLATE.md`, one authorized operational
non-production pilot, and an independent security review. Reviewers must
disclose conflicts, document all failures and sign the final artifact.

**Current external evidence counters:** installations = 0/5;
consented organizational pilots = 0; independent signed security reports = 0.
These figures must not be incremented because this runbook or a CI job exists.

## Privacy and responsible disclosure
Send security vulnerabilities privately through repository security
advisories or a channel agreed with the maintainer; avoid putting
unpatched exploit details, customer names, employee identities, session
tokens, tenant identifiers or unredacted data in public Issues.

Existing tracking: [#35](https://github.com/jandromani/faraday/issues/35)
for HA, [#42](https://github.com/jandromani/faraday/issues/42)
for external security sign-off and
[#43](https://github.com/jandromani/faraday/issues/43)
for adoption/pilot evidence.
