# R3 — Reliable Runtime (E15–E19, E21, E26, E27)

Status: **candidate controls in progress — not accepted, not production-HA**.

Existing modules (local single-node budget, Sentinel, approvals, journal backup,
synthetic TimeMachine) are useful foundations, not proof of multi-node guarantees.

## Acceptance requirements

- **E15 Idempotency:** retry with identical operation ID + payload cannot apply twice;
  conflicting payload with same ID must be denied, including after process restart.
- **E16 Recovery/HA:** adversarial crash before/after commit, signed backup restore,
  monotonic rollback pin, two-node failover, and split-brain fencing with no dual writer.
- **E17 Resource governance:** atomic agent and organization quota under concurrency;
  bounds include storage and timeouts, plus a measured p95 SLO.
- **E18 Human approval:** separate human keys, expiry, binding to capability and arguments,
  quorum and key-collision prevention, including revoked approvals.
- **E19 Sentinel:** quarantine, kill switch, durable outbox, tamper detection, operator-reviewed recovery.
- **E21 TimeMachine:** offline replay only: no tool invocation or external side effects.
- **E26 Fuzz/Chaos:** reproducible corpus and fault injection; no successful unsafe bypass.
- **E27 Benchmarks:** publish p50/p95/p99, hardware/OS, baseline, samples and allowed regression.

## Blocking gates
`lib/r3-runtime-gate.js` is a *manifest acceptance validator only*. Its
`evidenceIndependentlyVerified` field MUST be set by a trusted collector after
comparing actual bytes to each declared SHA-256. Do not accept untrusted callers'
assertion of this field as evidence. Live distributed HA, split-brain fencing,
failure injection and benchmarks must run against the same commit before R3 closes.

Never infer HA from SQLite single-process transactions; never claim TimeMachine
replays real side effects. R1 GitHub runners and R2 live trust boundaries remain
independent blockers for a production readiness claim.
