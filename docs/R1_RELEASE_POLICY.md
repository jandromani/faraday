# FARADAY R1 — Release assurance and protected master

Status: **release pipeline prepared**, not a verified release until the workflow completes for a specific commit. A passing local test, queued workflow or code upload is not a build attestation.

## Verification gates

The manual workflow `FARADAY R1 Release Assurance and Attested Candidate` only runs on master and prevents artifact publication until:

1. Node/Python regressions, synthetic evaluations and package audit pass.
2. Blocking adversarial Docker tests pass; a bypass failure cannot be offset by other tests.
3. The pinned official JavaScript MCP client 1.32.2 connects through FARADAY to official Filesystem 2.0.1 on Linux, macOS and Windows with a read-only tool call.
4. A disposable **official Vault** instance must pass a least-privilege AppRole lifecycle: an isolated token can read only the designated KVv2 secret; denied admin, other-secret and write attempts must return 403; rotation, revocation and fresh-token recovery must succeed.
5. A package installs offline on all three systems. The **Windows ACL safety rejection remains expected**, not an automatic Windows installation pass.
6. The local package archive matches **every source-file hash** in an SPDX 2.3 inventory, including archive path validation and pinned commit identity.
7. GitHub OIDC/Sigstore creates a provenance attestation, and GitHub CLI verifies it.

No npm publishing is implemented. With `publish_prerelease=false`, the workflow creates only a downloadable Actions artifact, not a GitHub Release. With `true`, GitHub creates a Developer Preview prerelease **only after every gate and attestation is successful**.

## Operator invocation and verification

GitHub → Actions → **FARADAY R1 Release Assurance and Attested Candidate** → Run workflow → `master`. Leave `publish_prerelease=false` for the first verified run.

```sh
gh attestation verify faraday-agentic-0.99.7.tgz -R jandromani/faraday
node scripts/release-candidate.mjs verify ./downloaded-directory EXACT_40_CHARACTER_COMMIT
```

The Node verifier checks archive bytes, SHA-256 and source-file inventory. GitHub's attestation establishes recorded CI provenance. A file inventory does **not** include all resolved dependencies and this is not an independent penetration test, reproducible-build guarantee or enterprise security certification.

## Mandatory branch ruleset — requires repository administrator

The connected GitHub integration cannot update branch protection (403 `Resource not accessible by integration`). An administrator must navigate to **Settings → Rules → Rulesets**, create and activate a ruleset targeting `master`, require pull requests, prevent force push/deletion, and require real (previously observed) CI job names: Graph + Docker, architecture blocking assurance, Security and MCP live interoperability. Use actual status-check names shown by GitHub; do not guess. Restrict and log emergency bypass permissions.

A workflow YAML change does not enforce branch protection. Verify the rule using the GitHub UI or REST after saving.

## Queue blocker

If jobs remain `queued` with no assigned runner, review each Actions run, repository Actions settings, account billing/minutes, concurrency and runner availability. GitHub's overall status can be operational despite a repository-specific queue. **Do not publish or label a release verified while those jobs remain queued.**
