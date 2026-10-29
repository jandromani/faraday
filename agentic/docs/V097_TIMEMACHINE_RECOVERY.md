# FARADAY v0.97 — Synthetic TimeMachine and Recovery Operations

**Status:** offline developer preview. No new production enforcement claim.

## Capabilities

- **E21:** deterministic capture of typed synthetic intents from 12 dummy actor profiles, hash-chained trace, corruption and inconsistent-outcome detection, offline replay with alternative role/tool/resource/action allowlist, and comparison of replay outcomes. No real network, filesystem tool, or business operation is re-executed.
- **E20:** optional offline comparison of caller-supplied observed decisions against the same `ToolPolicy` implementation used by the bridge and a proposed policy. A local HTTP test contrasts the result against a synthetic backend; it is not production telemetry or resource authorization.
- **E16:** read-only SQLite recovery inspector. Lists fresh/stale reservations and uncertain operations, requiring an operator to investigate. Never retries, deletes, or changes state. This **does not provide HA/failover**.
- **E27:** bounded local microbenchmarks with median and p95 for ToolPolicy and TimeMachine replay, using nearest-rank percentiles and reporting warmup iterations. Results depend on runner hardware and clock resolution; **not gateway latency or benchmark against competing products**.
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
faraday timemachine checkpoint --trace synthetic-trace.json --private-key witness.pem --witness local-witness --out checkpoint.json
faraday timemachine verify-checkpoint --trace synthetic-trace.json --checkpoint checkpoint.json --public-key witness-public.pem --witness local-witness [--expected-sha256 CHECKPOINT_DIGEST]
faraday recovery inspect --db .faraday/pilot-journal.sqlite --stale-ms 60000
faraday benchmark --iterations 200 --out benchmark.json
```

## Observed Decision Preflight

The operator may supply an explicit JSON array (at most 256 records and 512 KiB) to `faraday trust diff --base before.json --current after.json --observations observations.json --fail-on-divergence`:

```json
[
	{"server":"sandbox","message":{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_document","arguments":{}}},"observedAllowed":true}
]
```

`observedAllowed` is a caller-declared policy decision, not proof of a backend effect. The report includes only indexes and decisions, not messages or arguments; the input file itself may contain sensitive data and is neither encrypted nor automatically captured or deleted. Baseline mismatches and missing server configurations are reported separately; `--fail-on-divergence` exits nonzero for those cases, not simply because the proposed policy changes a decision. A missing server is a configuration error, not an ordinary denial. No tool or effect executes in the preflight, and it does not evaluate resource reachability, downstream permissions or causality. Bridge and proxy mediation are not universal boundaries.

## Synthetic Checkpoints

An optional Ed25519 checkpoint signs a SHA-256 digest of the complete synthetic trace, its root, step count, witness alias and claimed time. Verification requires a separately supplied public key and expected alias; it rejects a mismatched trace or signature. `checkpointDigest` in verification output is a SHA-256 hexadecimal digest of the canonical checkpoint. Supplying an independently retained `--expected-sha256` detects replacement by a different checkpoint, even if signed by the same key. Without a trusted external pin, an older or replacement signed checkpoint can be accepted.

The signing process and key are local unless the operator arranges otherwise. The alias and time are claims; a signature proves key possession, not independent custody, trusted time, actual execution or immutable retention. The checkpoint supports only synthetic TimeMachine traces. Private files and traces are not encrypted; Windows ACLs and path races are not verified.

## Unclosed scope

Real MCP event recording, secure encrypted/redacted capture, causality across processes, production HA, independently witnessed real-trace provenance, externally validated performance, and end-to-end external-framework interoperability remain open roadmap work.
