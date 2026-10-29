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

## Ownership and dependencies

The following are proposed engineering ownership roles, not claims that separate teams or runtime isolation exist. The integrator of the pilot gateway owns orchestration across them. Each owner reviews changes to its public entrypoint and contract tests; the security owner reviews any trust-boundary change.

| Owner | Owns | Existing dependency / forbidden assumption |
| --- | --- | --- |
| Connect maintainer | Discovery, proxy installation, adapter record validation and ingestion | Uses shared Graph storage and legacy modules; discovery and metadata are not authority decisions. |
| Authority maintainer | Policy, proof, capability and approvals verification | Provides authenticated decisions to the gateway; public exports are not an independent authorization service. |
| Evidence maintainer | Receipts, backend attestation verification, journal, synthetic replay and assurance | Receipt encoding uses Authority canonicalization; no receipt by itself authorizes an operation or proves a real-world effect. |
| Lab maintainer | Synthetic actors, scenarios and local evaluation | Exercises shared policy, contracts and replay implementations; results cannot certify production. |
| Pilot integration maintainer | Gateway orchestration, backend call and reconciliation | Connects legacy modules in one process; responsible for integration tests, error mapping and avoiding blind retries. |

## Current versioned data contracts

These are observed preview formats and validators, not independent wire-protocol guarantees. The API label `1.0.0-preview` is distinct from the npm package version and from each data-format version. Changes must preserve old readers or introduce an explicit migration; never reinterpret an existing version silently.

| Producer → consumer | Version and validation | Failure / compatibility boundary |
| --- | --- | --- |
| Python adapters → Connect ingestion | Metadata record `version: 1`; exact fields, known framework/kind/status, pseudonymous IDs and bounded elapsed time. | Unknown versions or raw extra fields are rejected; [adapter tests](../tests/adapter-ingest.test.js) use simulated SDKs. |
| Operator → Authority tool policy | `version: 1`, enforce mode, explicit per-server tool allowlist and argument-size bound. | Invalid policy is rejected; it covers mediated `tools/call`, not all methods or direct access. |
| Agent/issuer → Authority | Intent and execution proofs use `ver: 1`; capability claims use `v: 1`, signatures and exact-scope checks. | Invalid, expired, changed or replayed inputs fail closed; lifecycle and revocation remain local preview behavior. |
| Backend → Evidence | Backend attestation `version: 1`, exact claims, signed operation ID and request hash. | Invalid signature, different operation or digest is rejected; it attests a synthetic backend observation only. |
| Gateway → Evidence consumer | Receipt `version: 1`, exact claim keys and Ed25519 signature; signed backend attestation required to verify a simulated success when a backend key is supplied. | Unknown version or claim keys are rejected; uncertain outcomes require reconciliation. These checks do not prove external effects. |
| Evidence → Evidence consumer | Synthetic TimeMachine trace `version: 1`, schema, hash chain and replay consistency. | Unknown version or inconsistent trace is rejected; hashes do not authenticate provenance and replay has no real side effects. |
| Connect graph → contract diff | Contract snapshot `version: 1` with normalized schema shapes and bounded tools. | Unsupported snapshot version is rejected; unmodeled schema constraints require review. |

Cross-boundary tests in [architecture tests](../tests/architecture.test.js) resolve the four package exports and exercise local synthetic decisions, replay, and Authority-to-Evidence receipt verification. [Pilot tests](../tests/pilot.test.js) exercise actual loopback gateway requests and reject signed incompatible receipt schemas. Neither test runs independently deployed components or proves compatibility with future versions. Package-only import checks do not enforce the dependencies of transitive legacy `lib/*` modules.

## Migration gates

Before moving any implementation into an independently deployed component: (1) assign an owner and inventory its direct and transitive dependencies; (2) freeze versioned request/response schemas and test unknown versions, optional/required fields and old-reader/new-writer combinations; (3) remove private-key and credential access outside the owning process; (4) define authentication, transport, timeout, retry and uncertain-result semantics; (5) run cross-version integration and negative tests against independently built artifacts. A failed or skipped gate blocks claiming operational independence. No deployment isolation, compatibility matrix or ownership staffing has yet been established.

**Release gate:** no regressions to v0.99.3 CLI and 4 entrypoint imports pass.
