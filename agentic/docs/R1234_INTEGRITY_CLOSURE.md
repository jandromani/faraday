# R1–R4 integrity closure — operational instructions

**Status:** these changes implement byte-level R2/R3 evidence integrity and an optional R4 execution bridge. They do **not** certify R1, close R2/R3 or establish universal mandatory mediation.

## R2/R3 evidence collection
The existing scenario manifest must be created by a test runner that actually operates the target environment, e.g. Vault KVv2, a real OAuth IdP or two independent nodes. Store each scenario output as a regular JSON file under `agentic/artifacts/r2/` or `agentic/artifacts/r3/`, with at least `id`, `commit`, `result` and `execution`. The report references the exact SHA-256 of every file.

After collecting the outputs on the same checked-out commit:
```sh
cd agentic
npm run evidence:verify -- r2 artifacts/r2/manifest.json "$GITHUB_SHA"
npm run evidence:verify -- r3 artifacts/r3/manifest.json "$GITHUB_SHA"
```
The example paths assume the manifest is actually present there. Set `GITHUB_SHA` to the actual checked-out commit in CI. No sample or synthetic JSON is acceptable as live evidence.

The collector rejects: missing artifacts, changed digests, mismatched scenario/commit, symlinks, hardlinks, unsafe path traversal, oversized files and duplicate file references. It overrides caller-supplied flags only *after* comparing actual bytes and then applies the R2/R3 manifest validators. It returns `integrityPassed` and `manifestComplete`, **not** enterprise readiness. `releaseGatePassed` and `executionProvenanceVerified` remain false until independently verified runner provenance and live execution are available.

**Threat-model limit:** a malicious source can forge both a JSON file and its SHA-256. Digest verification detects alteration relative to a manifest; it does not attest who ran a test or whether it ran at all. Use externally verified CI provenance, signature and independent environmental inspection for acceptance. Do not promote a locally generated example to Secure Beta.

## R4 optional Authority-mediated execution
`createAuthorityMediatedAdapter` is exported from `@faraday/agentic/authority-adapter-bridge`.
The host supplies (1) an exact, observation-only adapter contract, (2) a live `AuthorityGate`, (3) a **fixed trusted** dispatcher, and optionally (4) an audit callback. For each call:
1. Reject undeclared `(tool, operation, resource)` triples before touching Authority.
2. Verify signed capability and proof, current policy, expiry, revocation and nonce via Authority.
3. Compare Authority's authenticated `tool, action, resource` against the declared triple.
4. Emit only sanitized metadata to the audit callback; if the callback fails, dispatch is blocked.
5. Invoke the host-controlled dispatcher exactly once from this bridge. **It is not a distributed exactly-once guarantee.**

This path is opt-in and does not capture unmediated SDK tool calls. Use deployment-level network isolation to prevent bypass. It has not been verified against real LangGraph, CrewAI or OpenAI Agents SDKs.

## Remaining blocking acceptance
- Issue #17: GitHub runners stay queued; restore execution and enable master ruleset with required checks.
- R1: run full 3-OS MCP + Docker, package tarball byte verification and Sigstore attestation on one SHA. Publish Developer Preview only after green gates.
- R2: real Vault, real IdP, hostile agent, backend network denial and receipts with independently verified source.
- R3: genuine two-node fencing, split-brain fault injection and measured p50/p95/p99 under repeatable load.
- R4: mandatory integration in each framework, scoped pilot and external onboarding.
