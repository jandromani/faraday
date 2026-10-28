# FARADAY v0.97 — Synthetic TimeMachine and Recovery Operations

**Status:** offline developer preview. No new production enforcement claim.

## Capabilities

- **E21:** deterministic capture of typed synthetic intents from 12 dummy actor profiles, hash-chained trace, corruption and inconsistent-outcome detection, offline replay with alternative role/tool/resource/action allowlist, and comparison of replay outcomes. No real network, filesystem tool, or business operation is re-executed.
- **E16:** read-only SQLite recovery inspector. Lists fresh/stale reservations and uncertain operations, requiring an operator to investigate. Never retries, deletes, or changes state. This **does not provide HA/failover**.
- **E27:** bounded local microbenchmarks with median and p95 for ToolPolicy and TimeMachine replay. Results depend on runner hardware; **not gateway latency or benchmark against competing products**.
- **E26:** regression tests for malformed trace, symlinks, unauthorized policy changes, idempotent duplicates, partial crashes and deterministic replay.
- **E28:** packaging remains private. Existing release audit generates SPDX 2.3 file inventory, SHA-256 manifest, and fails on potential credentials. This is **not a signed SBOM** or SLSA attestation.

## Safety invariants

1. Replay operates only on synthetic, schema-constrained intents and an in-memory state map.
2. Never sends requests or invokes installed MCP servers. Invalid or tampered trace is rejected before replay.
3. Trace chain cannot prove origin or protect against an attacker able to rewrite entire trace. Do not treat it as forensic evidence.
4. Recovery inspector opens the existing journal SQLite database read-only and never replays a reserved operation, because the backend may already have executed it.
5. Policy changes are simulations and cannot reauthorize an actual capability.

## Commands

```bash
faraday timemachine capture --seed 42 --out synthetic-trace.json
faraday timemachine replay --trace synthetic-trace.json --fail-on-divergence
faraday timemachine replay --trace synthetic-trace.json --policy tighter.json
faraday timemachine diff --base before.json --current after.json
faraday recovery inspect --db .faraday/pilot-journal.sqlite --stale-ms 60000
faraday benchmark --iterations 200 --out benchmark.json
```

## Unclosed scope

Real MCP event recording, secure encrypted/redacted capture, causality across processes, production HA, signed trace provenance, externally validated performance, and end-to-end external-framework interoperability remain open roadmap work.
