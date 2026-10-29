# ADR-001 — Four FARADAY module boundaries (2026-10-29)

**Decision:** introduce four versioned, private package API entrypoints without breaking the existing CLI or import paths. This is **migration phase 1**, NOT independent services yet.

| Package API | Responsibility | Boundary |
|---|---|---|
| Connect | MCP discovery, onboarding, adapters, configuration and ingestion | Must not make policy decisions |
| Authority | Identity, capabilities, signed approvals, OAuth resource checks | Must not export private issuer keys to the agent |
| Evidence | Signed receipts, Trace/TimeMachine, TrustDiff, privacy-safe telemetry and assurance | Must not authorize tool executions |
| Lab | Synthetic agents, attack corpus, evals and benchmarking | Must not hold live production credentials |

Entry points: `@faraday/agentic/connect`, `./authority-suite`, `./evidence`, `./lab-suite`. Version 0.99.4 and private package manifests. Current entrypoints delegate to historical `lib/*` code to preserve backwards compatibility. Tests verify the surfaces.

**Incomplete:** implementations are still co-located in `lib/*`; package-level dependency isolation is not yet enforced across legacy modules, and the four components cannot be deployed/published separately. Migration phase 2 must relocate implementations incrementally, introduce explicit signed/versioned cross-component contracts, and run integration tests after each move. The future console governs the four services; it must not become the cryptographic/data-plane monolith.

**Release gate:** no regressions to v0.99.3 CLI and 4 entrypoint imports pass.
