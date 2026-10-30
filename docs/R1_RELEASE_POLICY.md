# FARADAY R1 — Release assurance and protected master

Status: **release pipeline prepared for automatic SHA-pinned candidate attestation on master**, not a verified release until the workflow completes on the exact commit. A one-time GitHub Developer Preview prerelease is explicitly requested by the R5 rollout after all gates and hosted attestation succeed; it is not an npm release or a security certification. A passing local test, queued workflow or code upload is not a build attestation.

## Verification gates

The workflow `FARADAY R1 Release Assurance and Attested Candidate` runs automatically on a protected `master` push and can also be manually dispatched on master and prevents artifact publication until:

1. Node/Python regressions, synthetic evaluations and package audit pass.
2. Blocking adversarial Docker tests pass; a bypass failure cannot be offset by other tests.
3. The pinned official JavaScript MCP client 1.32.2 connects through FARADAY to official Filesystem 2.0.1 on Linux, macOS and Windows with a read-only tool call.
4. A disposable **official Vault** instance must pass a least-privilege AppRole lifecycle: an isolated token can read only the designated KVv2 secret; denied admin, other-secret and write attempts must return 403; rotation, revocation and fresh-token recovery must succeed.
5. A package installs offline on all three systems. Windows onboarding must perform a real install/uninstall with private backup ACL checks; rejection or SKIP is a failure.
6. The local package archive matches **every source-file hash** in an SPDX 2.3 inventory, including archive path validation and pinned commit identity.
7. GitHub OIDC/Sigstore creates a provenance attestation, and GitHub CLI verifies it.

No npm publishing is implemented. The first successful `master` push with this R5 rollout publishes the single immutable intended tag `v0.99.7-r5-preview` after all gates and attestation. Later automatic pushes detect the existing release and **do not publish another**. Explicit manual dispatch with `publish_prerelease=true` can create a separately numbered RC, again only after all gates. Check the release commit and provenance instead of trusting the title.

## Operator invocation and verification

A successful merge into protected `master` automatically runs all R1 gates and uploads a SHA-pinned candidate with GitHub Sigstore provenance. The R5 release-rollout change enables one prerelease only, with a stable one-time tag and a fail-closed check for an existing tag. No npm publishing occurs. Alternatively, GitHub → Actions → **FARADAY R1 Release Assurance and Attested Candidate** → Run workflow → `master` with `publish_prerelease=false` for an explicit verification run. Use `true` only after checking the complete run, and note that the workflow re-runs all security and package gates.

```sh
gh attestation verify faraday-agentic-0.99.7.tgz -R jandromani/faraday
node scripts/release-candidate.mjs verify ./downloaded-directory EXACT_40_CHARACTER_COMMIT
```

The Node verifier checks archive bytes, SHA-256 and source-file inventory. GitHub's attestation establishes recorded CI provenance. A file inventory does **not** include all resolved dependencies and this is not an independent penetration test, reproducible-build guarantee or enterprise security certification.

## Mandatory branch ruleset — current enforcement and remaining risk

`FARADAY — Protected Master` is active with pull requests, deletion and force-push restrictions. As last inspected, its **required checks were only `security (3.11)`, `security (3.12)` and `security (3.13)`**, despite nine workflows passing on the prior merge. An administrator must add existing passing jobs for 15-epic acceptance, Docker/Vault, architecture and MCP. Keep checking actual `master` ruleset configuration: editing workflow YAML does not change GitHub branch protection. A merge with the other checks red MUST NOT be called release-certified.

A workflow YAML change does not enforce branch protection. Verify the rule using the GitHub UI or REST after saving.

## Runtime and provenance blockers

The previous `master` SHA `8a3be0ee922ec4c79d43825396ff9e7ec417b76e` passed 9/9 standard workflows. This does NOT establish a successful R1 attestation. This workflow must pass after merge at its own SHA, and `gh attestation verify` must confirm the hosted bundle. Queued, failed or skipped R1 gates block release. R1 is Developer Preview only, not independent penetration testing, corporate SSO, or multi-node HA.
