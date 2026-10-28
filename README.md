# FARADAY — Trust Fabric

> Intelligence proposes. Authority executes.

FARADAY is a zero-trust security fabric for autonomous AI agents. The **Authority Boundary** keeps permission to execute outside the LLM.

## Trust Fabric

- **Identity** — verifiable agent and workload identities
- **Channels** — authenticated tool communications
- **Authority** — default-deny decisions, narrow, expiring capabilities
- **Enclave** — isolated execution
- **Provenance** — evidence and auditability
- **Sentinel** — detection and response
- **Control** — governance and operations

## Build 001 — FARADAY Gate (Python standard-library proof of concept)

The first build demonstrates:

- HMAC-SHA256 signed capabilities, fixed audience `faraday-tool-executor`
- TTL of 1–300 seconds, cryptographically random token identifiers
- Exact binding to caller, tool and input arguments
- Default-deny sample policy for `agent_finance/pay_invoice`, `supplier_001`, EUR, 1–20,000 cents
- Atomic one-use token consumption with SQLite (restart-safe)
- Six standard-library unit tests and CLI demo
- **No real payment or tool execution**

Run with Python 3.11+:

```bash
python -m unittest discover -s tests -v
python faraday.py demo
```

## Security limitations

**Prototype only: do not use as a production authorization boundary.**

The issuer and gate are classes in a single process with a shared key; the caller's identity is only an asserted string, not an independently authenticated workload identity. There is no mandatory MCP/HTTP proxy, no network enforcement preventing direct tool access, no isolated issuer, no key rotation or revocation, and no tamper-evident audit trail. Spending tokens before execution fails closed but requires end-to-end idempotency and failure recovery for real side effects.

## Roadmap

1. **Build 002:** isolate issuer, enforce authenticated identities, asymmetric signatures, negative testing.
2. **Build 003:** mandatory MCP proxy and deny direct tool access, idempotent downstream adapters.
3. **Build 004:** sandboxed execution, persistent signed provenance, Sentinel detection, red-team testing.
4. **Build 005:** Control console in Next.js/Vercel; security enforcement runs in independently secured infrastructure.

Intended architecture: `apps/console`, `services/gate`, `services/issuer`, `services/mcp-proxy`, `packages/policies`.

Current state: Build 001 authorization-only prototype; not independently audited.
