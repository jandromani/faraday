# FARADAY Security Status

**Developer Preview only.** The current pilot has opt-in OAuth resource validation and a limited MCP HTTP endpoint, not a complete OAuth server or universal MCP implementation. A historical Docker test covers one synthetic network topology, not general network containment. Agent proof-of-possession is not workload attestation. Never reuse demo keys for real data or production workflows. See [docs/V09_AUTHORITY_PREVIEW.md](docs/V09_AUTHORITY_PREVIEW.md) and [docs/ADR-002-GATEWAY-MAKE-OR-BUY.md](docs/ADR-002-GATEWAY-MAKE-OR-BUY.md).

The [internal STRIDE risk register and attack trees](docs/THREAT_MODEL.md) describe topology-specific assumptions, control owners, tests and required deployment controls. They are not an independent assessment.

---

# FARADAY Shield — Security model (Build 007)

**Status:** experimental hardening of FARADAY Agentic 0.7.0. **This is not a certified sandbox or an end-to-end zero-trust boundary.** Software cannot provide 100% security. Our goal is explicit trust boundaries, reproducible negative tests, and clearly disclosed residual risk.

## Security layers

1. **Discover** — read-only inventory; no tools executed by scanning. Secrets, commands, full URLs, arguments and tool results are not logged. Sensitive labels are redacted or pseudonymized for external AI.
2. **Shield Policy** — opt-in deterministic, per-server, exact MCP `tools/call` allowlist, with configurable maximum argument bytes. Optional `allowedMethods` restricts client-to-server methods on the configured proxy and HTTP bridge. Without it, non-tool methods pass through. Direct API calls, unmediated clients, server-to-client requests and semantic resource authorization require separate controls.
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

For an explicit client-to-server method allowlist, add for example `"allowedMethods":["initialize","notifications/initialized","ping","tools/list","tools/call"]`. Only exactly listed methods pass, and `tools/call` must also pass the tool allowlist and argument limit. An empty list denies all client frames; omitting the field preserves the legacy pass-through of non-tool methods. This mode also drops client responses without a method, so protocols using server-initiated requests such as sampling may not work. It does not filter server-to-client traffic. TrustDiff reports additions and removal of the method restriction as potential authority expansion.

**This is not automatically safe for any named tool:** e.g., `read_document` could exfiltrate confidential records and `list_documents` could still access unauthorized data. True authorization must authenticate identities, bind scopes to resources and users, use an external execution boundary, and prevent direct API bypasses.

## Threat / control / residual risk

| Threat | Build 007 control | Residual risk / required production control |
| --- | --- | --- |
| SSRF through HTTPS-to-private DNS rebinding | Validate every DNS answer and pin selected public address into socket lookup; no redirects | Explicitly allowed loopback can reach local services; configure network sandbox/egress firewall for robust isolation. IP lists may require updating. |
| Tool misuse / prompt injection | Tool allowlist enforced locally at `tools/call` | Tool argument semantic validation, user/resource authorization and full prompt-injection resilience are **not** provided. |
| Agent calls tool directly | None; proxy only governs mediated traffic; [loopback test](tests/shield.test.js) demonstrates a direct bypass | No-bypass requires network segmentation, scoped credentials and mandatory mediation, verified in each deployment. |
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

`graph clear` separately previews or atomically deletes all rows from the four known graph tables and the adapter-import deduplication index if present, not a particular person or organization. It does not remove other tables, journals, WAL/free pages, backups or exports, and active writers may repopulate the graph. Operators must define retention periods, access control, encryption and backup deletion for their deployment; no tenant isolation or complete erasure is provided.

The pilot requires HTTPS for non-loopback backend endpoints unless the operator explicitly enables insecure HTTP. Its Docker fixture enables that exception on a synthetic private network; the service credential is not encrypted in transit there. The optional Vault KV v2 reader is tested only against a local simulated server, not a real Vault deployment; it does not issue or rotate backend credentials, isolate tenants, or provide KMS. It may be invoked before signature verification, so access and request rates need independent controls. Windows ACLs and path races are not verified. See [pilot custody limits](docs/V095_SECURE_PILOT.md). Unverified backend responses remain uncertain and require reconciliation rather than an automatic retry. Signed receipts attest synthetic observations, not external business effects.

| Threat | Control and evidence | Remaining gap |
| --- | --- | --- |
| Forged identity or changed arguments | Capability plus agent proof and exact argument binding; [authority tests](tests/authority.test.js) and [pilot tests](tests/pilot.test.js) | No workload attestation or external identity lifecycle. |
| Policy outage or stale authorization | Optional fail-closed filter before Authority; [pilot tests](tests/pilot.test.js) cover timeout, key and persistent local agent revocation, expired approval, OAuth and emergency stop during the wait | The callback is not a universal mandatory gateway; claimed identifiers are unverified when sent. Ledger revocation does not propagate or cancel an already-authorized operation. |
| Direct access to the backend | Service secret and historical synthetic Docker topology; local tests show redirect blocking and successful bypass with the secret | No general no-bypass guarantee; network isolation and credential handling must be validated for each deployment. |
| Container escape or unrestricted egress | A separate rogue-tool probe and positive network control are configured for the synthetic Docker pilot; probe logic is tested locally | Updated containers were not run here. The probe covers selected files and destinations, not arbitrary egress, host isolation or untrusted real MCP tools. |
| Ambiguous side effect | Signed gateway/backend evidence and [reconciliation test](tests/reconcile.test.js) without re-execution | Fixture only; real services require their own idempotency, status and reconciliation contract. |
| Lost or stale journal | SQLite online snapshot, signed digest, new-path restore and optional external digest pin; [backup tests](tests/journal-backup.test.js) | Journal only, unencrypted, without independently managed anchor, nonce/backend recovery, automatic failover or measured RPO/RTO. A restored journal alone must not resume execution. |
| Evidence rollback or forgery | [Checkpoint tests](tests/evidence-checkpoint.test.js) cover chained receipts, a third signing key and a previously trusted prefix | Separate keys do not prove separate custody; external anchoring, trusted time and independent confirmation of real effects are not supplied. |
| Quota or approval bypass | Local agent/organization call counters and distinct agent/approver keys; [operator tests](tests/operator-controls.test.js) exercise concurrent SQLite consumption and signed approvals | Static mappings do not establish tenant or human identity; no distributed budgets, resource metering, durable alerts, SSO or authenticated rejection workflow. Stored approval bundles are not immutable or bound to the signed receipt. |
| Incident response failure | Local quarantine and control events are atomically queued for explicit HTTPS delivery; guarded recovery compares the reviewed chain head; [operator tests](tests/operator-controls.test.js) use simulated transport and local processes | No authenticated operator or receiver, automatic delivery, exactly-once ingestion, immutable evidence, trusted clock or distributed quarantine. Legacy resume bypasses guarded recovery. |
| Misinterpreted preflight or trace | ToolPolicy decisions can be compared offline with explicit observations; synthetic traces support optional signed checkpoints and externally retained pins | Observations are unverified and may contain sensitive arguments; the checkpoint does not establish independent custody, real capture, trusted time or causal effects. |
| Memory contamination | [MemoryGuard tests](tests/memory-guard.test.js) cover signed sources, default quarantine, explicit local review and exact structured fact conflicts | No semantic injection detection, authenticated reviewer, immutable audit, encryption, mandatory RAG integration or guarantee that signed content is safe. |
| Local credential disclosure | Windows auto-install refuses to create backups without verified ACL protection; [installer tests](tests/discover.test.js) | Existing backups and ACLs are not automatically secured or validated. |

This is a scoped internal threat model, not an independent review or complete STRIDE assessment.

Security guidance: [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices), [OWASP MCP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html), [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10/).

## Build 008 findings

FARADAY Lab is intentionally synthetic. Its fixed 1,000 cases contain 350 explicitly unsupported evaluations; never use the 650/650 verified checks as a general security percentage. `faraday lab run --fail-on-gap` is expected to fail until those controls exist. TrustDiff compares configured allowlists, not semantic authority or direct API reachability. Read [V08_SCOPE](docs/V08_SCOPE.md).
