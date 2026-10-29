# FARADAY v0.99 — Synthetic Agentic End-to-End

**Stage:** Developer Preview / synthetic secure pilot. **No live payments, no attested runtime, no enterprise guarantees.**

## The integrated path

1. **Model or deterministic dummy** returns a proposed action as raw JSON. Default is offline, with no model call.
2. **Deterministic scope check** independently validates one fixed fake invoice operation. A model cannot mint an authorization, approve itself, choose a new recipient, or access credentials.
3. **Trusted issuer** checks an Ed25519-signed intent and creates a single-use, scoped capability. The synthetic harness supplies agent signing identity and private issuer key: this is NOT how an untrusted production LLM should be deployed.
4. **Trusted approvers**, NOT the LLM, create two Ed25519 signed fixture approvals bound to exact capability and argument digest. In a real environment these approvals require external authorized humans/identities; the demo simulates consent.
5. **MCP Gateway** validates identity proof, signed capability, double approval, tool/action/resource/arguments, and replay protections.
6. **Synthetic backend** validates a separate service credential, performs one idempotent fake operation, and signs its own attestation.
7. **Evidence** includes signed gateway and backend receipt within a local hash-chained trace. `workflow verify` checks the signatures offline; **verification never re-invokes any tool**.

## Run offline (zero external network or inference cost)

```bash
cd agentic
npm run workflow
faraday workflow demo --out trace.json
faraday workflow verify --trace trace.json
faraday workflow eval --limit 100 --out e2e-evals.json
```

The `--out` flag uses exclusive file creation (`wx`) to avoid overwriting existing evidence; files are created private where supported.

## Optional live free-only model (requires YOUR local OpenRouter key)

```bash
export OPENROUTER_API_KEY='configure-privately-in-your-shell-or-secret-manager'
faraday workflow live --send-intent --model openrouter/free --out evidence.json
```

Do not paste a real key into tickets, this repository, scripts or chat. The exact task sent is a **synthetic, fixed, fake invoice plan with no personal/business data**. `--send-intent` grants explicit external transmission consent. The client checks OpenRouter's public pricing catalog before requesting a `:free` model or `openrouter/free`, refuses nonzero catalog prices, and rejects nonzero reported usage cost. **Provider prices can change between catalog lookup and inference; we cannot promise absolute $0 charges.** There is no paid fallback.

Free models can be rate-limited, output prose instead of strict JSON or decline. Such outputs **fail closed** and never execute a tool; use the default offline dummy to validate security and reproducibility. The live path remains opt-in and was not exercised by offline CI.

## What evaluations actually show

The v0.99 corpus consists of deterministic synthetic cases: legitimate actions, stolen key, mutated arguments, missing proof, missing approvals, capability replay, unauthorized direct backend access and untrusted prompt injection. Every accepted operation is backed by two signatures and is counted once. A successful evaluation does **not** imply runtime no-bypass on arbitrary networks: local loopback and the existing Docker reference topology have different threat models.

The hash chain is **not signed as a complete audit log**: an attacker able to rewrite the trace could delete denied events and recompute the chain. They still cannot forge a successful gateway/backend receipt without those signing keys. For non-repudiation of complete event ordering, add independently signed log checkpoints and external anchoring.

## Next gaps before a trusted production runtime

- Real workload identities, distributed policy, revocation and secret brokerage with independently verified participants.
- Real approval UX with person/role authentication instead of the harness's synthetic pre-approved signatures.
- General MCP methods, frameworks and policies (this demo only supports the synthetic `pay_invoice` tool).
- Signed immutable audit-head checkpoints, crash recovery across hosts and high-availability execution.
- Repeat Docker network-isolation and instrumented real-framework integration on every supported deployment target.
- Actual externally measured live free-model reliability and quality; offline tests mock the provider.
