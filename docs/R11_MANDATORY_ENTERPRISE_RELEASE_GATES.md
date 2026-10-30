# R11 — Mandatory zero-trust release and master gates

This release-gating change prevents a green Python check or signed candidate when
the full Keycloak+Vault+Authority+MCP integration or the real PostgreSQL
fenced-backend integration fails or is skipped.

## PR enforcement (indirect current GitHub ruleset)
- `FARADAY Security Tests` now invokes real official Keycloak/Vault and
  PostgreSQL integration workflows as **reusable jobs**, plus existing
  mandatory Node, official Vault, Docker and MCP client suite.
- All three existing required `security (3.11/3.12/3.13)` jobs explicitly
  fail if **any** prerequisite fails, is skipped or is canceled. GitHub's
  handling of skipped checks cannot silently green-light a PR.
- The current ruleset still directly names only those Python jobs. An
  administrator must eventually add the other contexts directly; this
  bridge is a fail-closed dependency, not a substitute for admin controls.
- The reusable workflows have non-canceling, distinct concurrency groups
  to avoid sibling jobs canceling each other.

## Release enforcement
`FARADAY R1 Release Assurance and Attested Candidate` now additionally
requires the reusable Keycloak/Vault and PostgreSQL workflows. The
`attest-candidate` job has both as `needs`, so a failure or skipped job
prevents building, signing or publishing the candidate.

## Evidence required
The R11 pull request and subsequent `master` run must show:
- Keycloak/Vault/Authority: actual signed JWT, controlled synthetic MCP call,
  secret read, revocation and renewed scoped token.
- PostgreSQL: actual MCP gateway and backend epoch fencing, 8 concurrent
  idempotent requests, storage pause and uncertain-outcome recovery.
- Node/Docker/Vault/MCP independent checks and Python matrix green.
- R1 candidate only after ALL upstream jobs pass and GitHub verifies
  provenance of exact archive and SHA.

## Hard limits
This is not independent approval, external attestation, SOC2/ISO27001,
hardening of multi-tenant prod IdP, nor production HA. Branch rule review
count remains zero because this connector lacks administration privileges,
and sole-maintainer approval could deadlock merges. A real additional
maintainer and administrative settings write must be arranged before
requiring external approval.
