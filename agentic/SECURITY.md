# FARADAY v0.9 Security Status

**Authority Preview only.** See [docs/V09_AUTHORITY_PREVIEW.md](docs/V09_AUTHORITY_PREVIEW.md). The v0.9 demo proves a specific Docker-isolated synthetic agent cannot reach its backend directly, not that FARADAY offers general network containment. Agent proof-of-possession is not workload attestation and the HTTP endpoint is not MCP OAuth. Never reuse demo keys for real data or production workflows.

---

# FARADAY Shield — Security model (Build 007)

**Status:** experimental hardening of FARADAY Agentic 0.7.0. **This is not a certified sandbox or an end-to-end zero-trust boundary.** Software cannot provide 100% security. Our goal is explicit trust boundaries, reproducible negative tests, and clearly disclosed residual risk.

## Security layers

1. **Discover** — read-only inventory; no tools executed by scanning. Secrets, commands, full URLs, arguments and tool results are not logged. Sensitive labels are redacted or pseudonymized for external AI.
2. **Shield Policy** — opt-in deterministic, per-server, exact MCP `tools/call` allowlist, with configurable maximum argument bytes. All tool calls are denied when an empty policy is activated. Tested with `stdio` and HTTP bridge adapters. It **only** covers tool calls through the configured FARADAY proxy. `resources/*`, `prompts/*`, sampling, direct API calls and unmediated clients require separate controls.
3. **Shield Egress** — configured HTTP bridge target must use HTTPS remotely, or HTTP to literal loopback/localhost. Public DNS results are validated and pinned into the actual socket connect (TLS name verification retained). Private, reserved, loopback and metadata-service IP results are rejected for non-local hostnames. HTTP redirects are not followed. URL credentials and credential-bearing query parameters are forbidden. Response payloads and concurrently pending requests are bounded.
4. **Shield Data** — metadata-only observability, restricted local SQLite permissions, refusal to open symlinked database files, restricted configuration backups, read-only local posture audit. External OpenRouter use requires explicit consent; model must be listed as free immediately before any inference. Graph names and contract paths are replaced with ephemeral identifiers or coarse categories for external transmission.

## Quickstart: from passive to enforce

```bash
# Continue using passive discovery/observation safely, without modifying client prompts.
faraday security audit --root .
faraday doctor --root .

# Create an explicit deny-by-default policy and edit its allowedTools array.
faraday security policy-template --server my-mcp > .faraday/shield.json
# Edit .faraday/shield.json to allow only the tool names required.

# Review configuration changes before enabling enforcement.
faraday install --dry-run --config .mcp.json --server my-mcp --policy .faraday/shield.json
faraday install --config .mcp.json --server my-mcp --policy .faraday/shield.json

# Roll back the client configuration (policy file remains under user control).
faraday uninstall --config .mcp.json --server my-mcp
```

Policy v1 format:

```json
{"version":1,"mode":"enforce","maxArgumentBytes":8192,"allowedTools":{"my-mcp":["read_document","list_documents"]}}
```

**This is not automatically safe for any named tool:** e.g., `read_document` could exfiltrate confidential records and `list_documents` could still access unauthorized data. True authorization must authenticate identities, bind scopes to resources and users, use an external execution boundary, and prevent direct API bypasses.

## Threat / control / residual risk

| Threat | Build 007 control | Residual risk / required production control |
| --- | --- | --- |
| SSRF through HTTPS-to-private DNS rebinding | Validate every DNS answer and pin selected public address into socket lookup; no redirects | Explicitly allowed loopback can reach local services; configure network sandbox/egress firewall for robust isolation. IP lists may require updating. |
| Tool misuse / prompt injection | Tool allowlist enforced locally at `tools/call` | Tool argument semantic validation, user/resource authorization and full prompt-injection resilience are **not** provided. |
| Agent calls tool directly | None; proxy only governs mediated traffic | No-bypass requires network segmentation, scoped credentials and mandatory mediation. |
| Credential theft from MCP backup | 0600 backup and private directory, no credential content in logs | Operating-system compromise, process env leakage and malicious MCP tools remain in scope. |
| Unauthorized local dashboard access | Loopback-only listener, random token/cookie and CSP | Local machine compromise and deliberate disclosure of link/session remain possible. |
| Excessive MCP responses or concurrency | Frame, HTTP body and pending-call limits | Malicious stdio children are not sandboxed; broader memory/CPU DoS testing needed. |
| Exfiltration via external AI | External opt-in, pseudonymized topology, free-only model check | Topology shapes and statistics can themselves be sensitive; **do not send confidential metadata without approval**. Billing/free quota can change after catalogue verification. |
| Malicious tool metadata/schema | Structural contracts and drift reporting | Not a complete tool-description or prompt-injection detector; no external independent signature attestation. |
| Audit/data integrity | SQLite graph and local posture checks | Not tamper-evident: local users/processes can edit database or logs. |
| Supply-chain compromise | No runtime npm dependencies | Node/tooling provenance, code signing, SBOM, artifact signatures and external audit still needed. |

## Disclosure and verification

- `npm test`: security-related tests in `tests/egress-guard.test.js`, `tests/security-policy.test.js`, `tests/security-audit.test.js` plus the existing suite.
- CI runs Node.js 22 and 24. The fixed corpus passing does **not** prove zero vulnerabilities.
- Please do not transmit real secrets or sensitive information to an external model unless explicitly authorized and screened. API keys belong in environment/secret stores, not in GitHub or policy JSON.
- This release is an optional defensive shim and observability toolkit. It is **not** an independent identity authority, privileged KMS, process sandbox or production compliance certification.

Security guidance: [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices), [OWASP MCP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html), [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10/).

## Build 008 findings

FARADAY Lab is intentionally synthetic. Its fixed 1,000 cases contain 350 explicitly unsupported evaluations; never use the 650/650 verified checks as a general security percentage. `faraday lab run --fail-on-gap` is expected to fail until those controls exist. TrustDiff compares configured allowlists, not semantic authority or direct API reachability. Read [V08_SCOPE](docs/V08_SCOPE.md).
