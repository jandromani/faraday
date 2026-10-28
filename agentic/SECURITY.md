# FARADAY Shield — Build 007 security model

**Experimental hardening, not a certified sandbox or an end-to-end zero-trust boundary.** Nobody can guarantee 100% security. Security claims are limited to the mediated tool path and fixed test corpus.

## Threat model

| Threat | Control | Residual risk |
| --- | --- | --- |
| SSRF / DNS rebinding | Validate DNS A/AAAA and pin public IP into actual HTTPS socket; block private/reserved destinations and redirects | Explicit loopback can still reach local services; network firewall remains essential |
| Tool misuse / injection | Optional exact per-server MCP tool allowlist, default-deny when enabled | Only covers mediated tools/call. No semantic argument validation or direct-API bypass protection |
| Resource exhaustion | Bounded HTTP responses, concurrent requests and frames | No process sandbox for stdio children |
| Secret disclosure | Metadata-only logging, restricted database permissions, private 0600 backups | A malicious local process could still access process environment |
| AI exfiltration | External consent, pseudonymized graph identities and sanitized contract summaries | Graph topology itself can still be sensitive; free tier billing may change |
| Local dashboard | Loopback listener, access token, CSP | Machine compromise remains possible |
| Tool poisoning | Structural contract snapshots and drift detection | Does not independently authenticate tools/descriptions or defeat prompt injection |
| Supply-chain | No runtime npm dependencies | Node version and artifacts must still be signed and audited |

## Usage

No policy file means passive observation. Enabling a policy explicitly denies all unlisted tool names.

~~~bash
faraday init --root .
faraday security audit --root .
faraday security policy-template --server my-server > .faraday/shield.json
# Edit allowedTools in .faraday/shield.json
faraday install --dry-run --config .mcp.json --server my-server --policy .faraday/shield.json
faraday install --config .mcp.json --server my-server --policy .faraday/shield.json
# Revert:
faraday uninstall --config .mcp.json --server my-server
~~~

Example JSON:
~~~json
{"version":1,"mode":"enforce","maxArgumentBytes":8192,"allowedTools":{"my-server":["read_document"]}}
~~~

A tool named read_document may still read sensitive resources. Production claims require workload attestation, authenticated human/agent identity, per-resource authorization, isolated egress, signed receipts, approved tools and mandatory no-bypass enforcement.

## Verification and disclosure

CI tests Node.js 22 and 24. Local security audit checks permissions but is not a penetration test. Keep .faraday private and excluded from version control. No paid fallback for external OpenRouter inference. Catalogue prices can change; nobody can promise 0 USD under all conditions.

Sources: [MCP security best practices](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/docs/2026-07-28/tutorials/security/security_best_practices.mdx), [OWASP MCP security cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html), [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10/).

## Build 008 findings

FARADAY Lab's 1,000 fixed synthetic scenarios contain 350 explicitly unsupported evaluations; the other 650 are repeated deterministic checks over a narrow corpus, not a security percentage. `faraday lab run --fail-on-gap` exits 2 as expected. TrustDiff compares tool allowlists, not semantic authority or direct API reachability. See [scope](docs/V08_SCOPE.md).
