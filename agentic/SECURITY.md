# FARADAY Security Status

**Developer Preview only.** The current pilot has opt-in OAuth resource validation and a limited MCP HTTP endpoint, not a complete OAuth server or universal MCP implementation. A historical Docker test covers one synthetic network topology, not general network containment. Agent proof-of-possession is not workload attestation. Never reuse demo keys for real data or production workflows. See [docs/V09_AUTHORITY_PREVIEW.md](docs/V09_AUTHORITY_PREVIEW.md) and [docs/ADR-002-GATEWAY-MAKE-OR-BUY.md](docs/ADR-002-GATEWAY-MAKE-OR-BUY.md).

---

# FARADAY Shield — Security model (Build 007)

**Status:** experimental hardening of FARADAY Agentic 0.7.0. **This is not a certified sandbox or an end-to-end zero-trust boundary.** Software cannot provide 100% security. Our goal is explicit trust boundaries, reproducible negative tests, and clearly disclosed residual risk.

## Security layers

1. **Discover** — read-only inventory; no tools executed by scanning. Secrets, commands, full URLs, arguments and tool results are not logged. Sensitive labels are redacted or pseudonymized for external AI.
2. **Shield Policy** — opt-in deterministic, per-server, exact MCP `tools/call` allowlist, with configurable maximum argument bytes. All tool calls are denied when an empty policy is activated. Tested with `stdio` and HTTP bridge adapters. It **only** covers tool calls through the configured FARADAY proxy. `resources/*`, `prompts/*`, sampling, direct API calls and unmediated clients require separate controls.
3. **Shield Egress** — configured HTTP bridge target must use HTTPS remotely, or HTTP to literal loopback/localhost. Public DNS results are validated and pinned into the actual socket connect (TLS name verification retained). Private, reserved, loopback and metadata-service IP results are rejected for non-local hostnames. HTTP redirects are not followed. URL credentials and credential-bearing query parameters are forbidden. Response payloads and concurrently pending requests are bounded.
4. **Shield Data** — metadata-only observability, POSIX file modes where supported, refusal to open symlinked database files and a read-only local posture audit. Windows ACLs are not verified; automatic proxy installation is disabled there because backups may contain credentials. Existing backups require owner review. External OpenRouter use requires explicit consent; model must be listed as free immediately before any inference. Graph names and contract paths are replaced with ephemeral identifiers or coarse categories for external transmission.

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
# Automatic installation is currently unavailable on Windows.
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
| Credential theft from MCP backup | POSIX 0600 backup and private directory; Windows auto-install fails before backup creation | POSIX modes do not verify Windows ACLs; existing Windows backups, privileged users, process env leakage and malicious MCP tools remain risks. |
| Unauthorized local dashboard access | Loopback-only listener, random token/cookie and CSP | Local machine compromise and deliberate disclosure of link/session remain possible. |
| Excessive MCP responses or concurrency | Frame, HTTP body and pending-call limits | Malicious stdio children are not sandboxed; broader memory/CPU DoS testing needed. |
| Exfiltration via external AI | External opt-in, pseudonymized topology, free-only model check | Topology shapes and statistics can themselves be sensitive; **do not send confidential metadata without approval**. Billing/free quota can change after catalogue verification. |
| Malicious tool metadata/schema | Structural contracts and drift reporting | Not a complete tool-description or prompt-injection detector; no external independent signature attestation. |
| Audit/data integrity | SQLite graph and local posture checks | Not tamper-evident: local users/processes can edit database or logs. |
| Supply-chain compromise | No runtime npm dependencies | Node/tooling provenance, code signing, SBOM, artifact signatures and external audit still needed. |

## Disclosure and verification

`faraday security audit` returns a nonzero exit status for both identified failures and items requiring review. An unknown Windows ACL is a review, not a pass. The local audit does not establish that an ACL is private or scan arbitrary files for secrets.

- `npm test`: security-related tests in `tests/egress-guard.test.js`, `tests/security-policy.test.js`, `tests/security-audit.test.js` plus the existing suite.
- CI runs Node.js 22 and 24. The fixed corpus passing does **not** prove zero vulnerabilities.
- Please do not transmit real secrets or sensitive information to an external model unless explicitly authorized and screened. API keys belong in environment/secret stores, not in GitHub or policy JSON.
- This release is an optional defensive shim and observability toolkit. It is **not** an independent identity authority, privileged KMS, process sandbox or production compliance certification.

## Pilot trust boundaries

Assets include agent and issuer keys, service credentials, signed capabilities, approvals, arguments, journals and receipts. The pilot treats client-supplied headers, RPC bodies and external-policy verdicts as untrusted. Its trusted operator configures issuer keys, agent registry, policies, backend endpoint and signing keys. A compromised operator, host or trusted backend is outside the controls demonstrated by the local tests. Event pruning is manual, affects only graph event rows and is not secure erasure; graph aggregates, other stores, WAL and backups may retain data.

The pilot requires HTTPS for non-loopback backend endpoints unless the operator explicitly enables insecure HTTP. Its Docker fixture enables that exception on a synthetic private network; the service credential is not encrypted in transit there. This is not a Vault/KMS integration or credential rotation. Unverified backend responses remain uncertain and require reconciliation rather than an automatic retry. Signed receipts attest synthetic observations, not external business effects.

| Threat | Control and evidence | Remaining gap |
| --- | --- | --- |
| Forged identity or changed arguments | Capability plus agent proof and exact argument binding; [authority tests](tests/authority.test.js) and [pilot tests](tests/pilot.test.js) | No workload attestation or external identity lifecycle. |
| Policy outage or stale authorization | Optional fail-closed filter before Authority; [pilot tests](tests/pilot.test.js) cover timeout, key revocation, expired approval, OAuth and emergency stop during the wait | The callback is not a gateway integration and claimed identifiers are unverified when sent. |
| Direct access to the backend | Service secret and historical synthetic Docker topology | No general no-bypass guarantee; network isolation and credential handling must be validated for each deployment. |
| Ambiguous side effect | Signed gateway/backend evidence and [reconciliation test](tests/reconcile.test.js) without re-execution | Fixture only; real services require their own idempotency, status and reconciliation contract. |
| Local credential disclosure | Windows auto-install refuses to create backups without verified ACL protection; [installer tests](tests/discover.test.js) | Existing backups and ACLs are not automatically secured or validated. |

This is a scoped internal threat model, not an independent review or complete STRIDE assessment.

Security guidance: [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices), [OWASP MCP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html), [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10/).

## Build 008 findings

FARADAY Lab is intentionally synthetic. Its fixed 1,000 cases contain 350 explicitly unsupported evaluations; never use the 650/650 verified checks as a general security percentage. `faraday lab run --fail-on-gap` is expected to fail until those controls exist. TrustDiff compares configured allowlists, not semantic authority or direct API reachability. Read [V08_SCOPE](docs/V08_SCOPE.md).
