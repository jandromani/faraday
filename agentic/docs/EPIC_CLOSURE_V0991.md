# FARADAY v0.99.1 — 15 scoped acceptance gates

**Scope: Developer Preview. Not an enterprise-security certification.**

This release converts the 15 roadmap candidates into *machine-checkable acceptance contracts*, rather than silently marking a broad enterprise epic "done" when only one prototype exists. The original 32 epics remain open at their enterprise scope. Only explicitly delimited Developer Preview deliverables can be signed off.

## Evidence

- `docs/EPIC_CLOSURE_SCOPE_V1.json`: machine-readable, versioned contract for 15 E01/E05/E06/E07/E08/E10/E14/E17/E20/E21/E23/E25/E26/E27/E28 checks and 15 threat/control/test/residual-risk mappings.
- `tests/closure-acceptance.test.js`: 15 focused tests invoking real FARADAY modules. These **are not 15 new security properties**: most reinforce previously exercised parts of the same implementation.
- `scripts/epic-closure-report.mjs`: runs gates, fails closed on missing, duplicate or failed IDs, writes per-run JSON with version/Node/OS/commit and SHA-256 digest.
- `.github/workflows/epic-closure.yml`: checks Node 22/24 Linux and Node 24 macOS/Windows plus the full Linux regression. A matrix job passing proves these scoped checks on that runner; it does not prove compatibility with all user environments.

## Eight existing technical deliverables: candidate to close at scoped Developer Preview level

| Epic | Check | Scope we can sign off after successful CI | What stays open |
|---|---|---|---|
| E07 | Optional Python framework adapters installed and tested | Opt-in wrappers for three known SDK APIs | No compulsory coverage or universal SDK compatibility |
| E08 | Graph with metadata and scrubbed contracts | Configured/observed graph, safe normalized schemas | No complete causality or all agent frameworks |
| E10 | Exact-scope capability and PoP | Synthetic issuer+gateway deny non-permitted resource or fake key | No distributed IAM/OIDC production attestation |
| E14 | Signed synthetic operation receipts | Gateway/backend independent signatures in local demo | No independently verifiable external business effects |
| E21 | Synthetic offline TimeMachine | Detect tampering, reproduce state without effects | No real production workflow replay |
| E23 | Synthetic agent lab | 12 actors, seeded 1,000-case corpus including 350 GAP | No autonomous real-model swarm simulation |
| E25 | Compatibility reporting | Explicit distinction between discovery and SDK tests | No MCP-wide conformance certification |
| E27 | Offline benchmark harness | Bounded local p50/p95 measurements with caveats | No end-to-end latency SLA |

## Seven additional candidate technical gates (not entire epic closure)

| Epic | Added acceptance | Still needs for original close |
|---|---|---|
| E01 | Threat-control-test-risk table | Security review and full STRIDE/abuse case assessment |
| E05 | Reversible config installer test and multi-OS CI | Real clients on each OS, packaging and end-user UX |
| E06 | Transport inventory and truthfully unsupported SSE | MCP feature matrix, OAuth, actual client-server conformance |
| E17 | Persistent SQLite quotas and exhaustion checks | Multi-node rate accounting, clock skew, fairness and load |
| E20 | Conservatively classified TrustDiff/contracts preflight | Causal impact of actual executions |
| E26 | Seeded attack corpus consistency and existing signed mutations | Coverage-guided fuzzing and chaos engineering |
| E28 | Package inventory, hashes, basic secret guard | Artifact signatures, SLSA provenance, independent SCA scans |

## Run and validate

```bash
cd agentic
npm run test:all
npm run closure:test
npm run closure:report
node scripts/epic-closure-report.mjs --out epic-evidence.json
```

`epic-evidence.json` is a local, **unsigned** summary. Its SHA-256 identifies the manifest content but does not provide independent authenticity. CI artifacts and commit SHA provide traceability, not security certification. This system intentionally refuses to claim the 350 deferred eval scenarios have passed.

## Release rule

A scoped acceptance may only be marked validated if its check and full existing regression pass on the source commit. Multi-OS checks are additional evidence for E05/E06. Do **not** set an original epic to `enterpriseClosed` unless independent validation covers the original scope. The JSON reporter currently emits `enterpriseClosed: 0` by design.
