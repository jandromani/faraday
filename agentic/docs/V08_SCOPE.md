# FARADAY Graph v0.8.0 — Developer Preview

**Not a production zero-trust boundary, an audited sandbox, or a published npm registry package.**

## Delivered
- Existing v0.7 discovery, local stdio proxy and HTTP adapter, structural tool contracts, reversible installation and Shield allowlist.
- TrustDiff for tool allowlist expansions, removals and argument byte-limit changes. This is not runtime reachability analysis.
- Static Compatibility Matrix: configured servers and eligible transports, never mislabeled as externally conformance-tested.
- Twelve synthetic agent profiles and an executable local MCP fixture with twelve simulated tools.
- Exactly 1,000 reproducible scenarios, deterministic evaluation report, and CI coverage.
- New CLI commands; package remains private for npm registry and installable from local source/TGZ.

## Evaluation corpus

| Category | Scenarios | Expected status |
| --- | ---: | --- |
| Legitimate allowlisted tools | 250 | 250 pass |
| Unauthorized tool name | 200 | 200 pass |
| Prompt injection | 150 | 150 gap |
| Unsafe URL target rejection | 100 | 100 pass |
| Authenticated workload identity | 100 | 100 gap |
| Chaos/recovery and idempotency | 100 | 100 gap |
| Structural contract breaking changes | 100 | 100 pass |

**650 passes, 0 failures, 350 gaps** for fixed seed 42, not 650 separate security exploits.
The assertion logic is reused across synthetic variants. No live agent model, real bank API, browser, internet or production tool is involved.

## Usage

```bash
npm install -g ./faraday-agentic-0.8.0.tgz
faraday init --root /project --dry-run
faraday onboard --root /project
faraday compat --root /project
faraday lab agents
faraday lab fixture --out ./faraday-lab-fixture
faraday lab run --seed 42 --out ./faraday-evals.json
faraday lab run --fail-on-gap   # expected exit 2
faraday trust diff --base before.json --current after.json --fail-on-expansion
```

The generated fixture's `mcp.json` starts the `faraday-lab-server` using the local Node executable and package script. The server supports `tools/list` and `tools/call` for twelve `simulate_*` tools. Results have `SIMULATED_*` decisions and `executedExternally=false`.

## Gates before enterprise claims

- Actual external MCP client/server compatibility tests, across OS and protocol versions.
- Workload identity and cryptographic delegation with separate trust anchors.
- Mandatory no-bypass gateway, isolated executor, secrets broker and signed receipts.
- Red-team work and an independently reviewed threat model.
- Auditable, privacy-preserving logs and production resilience.

A passing synthetic lab does **not** prove these controls exist. [MCP Specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) changes HTTP transport and session semantics; FARADAY's HTTP bridge only supports a subset.
