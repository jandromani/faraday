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

## Current execution boundary

The table above describes module ownership, not process isolation. In the synthetic pilot the HTTP handler parses the MCP request, validates configured OAuth and approvals, optionally consults an external-policy callback, then calls the in-process Authority gate. Only after signature, exact-scope and replay checks does it reserve a journal entry and invoke the fixed synthetic backend. The backend returns its own signed attestation; Evidence signs a separate gateway receipt and stores the outcome. An uncertain backend result requires reconciliation without blindly repeating the operation.

The callback receives fingerprints of claimed identity and resource before Authority authenticates them; its allow decision cannot replace Authority. The gateway holds the backend service credential, so network isolation and credential distribution outside this process must be proven in the actual deployment. Discovery and observation paths do not enforce this pilot boundary. No separate services, mTLS, distributed transaction or universal no-bypass property follows from these API exports.

Existing local interfaces include signed capability and proof objects, policy inputs, journal records and signed receipts. They are implementation-specific preview contracts, not a finalized cross-service wire protocol. Any future service split needs an explicit versioned protocol, authentication, failure semantics and independent integration tests before moving the trust boundary.

**Release gate:** no regressions to v0.99.3 CLI and 4 entrypoint imports pass.
