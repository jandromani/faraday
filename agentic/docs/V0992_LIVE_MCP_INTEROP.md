# FARADAY v0.99.2 — Live MCP Interoperability & Cold Onboarding

**Scope:** E05/E06 developer-preview validation. This is *not* a claim of universal MCP compatibility, security enforcement, or deployment readiness.

## Live MCP probe

`faraday compat probe --config /path/mcp.json --server fixture` starts the **selected, preconfigured stdio server**; no other configured servers are executed. It tests:

- `server/discover` for the `2026-07-28` modern protocol; falls back on `-32601`/`-32022` to legacy `initialize` and `notifications/initialized` if the server explicitly rejects discovery.
- `tools/list` and pagination (bounded at 1–20 pages and at most 1,000 tools); verifies the response envelope.
- Process-scoped 200–60,000 ms timeout and a 2 MB stdout cap; output reports names (sanitized), counts, timings and protocol era only.
- **No tools execute by default.** `--call-tool exact_name --allow-call` explicitly executes a named tool with `{}` arguments, and never displays its response. Tool annotations are *not* treated as proof of read-only behavior. Use this flag only on known safe tools with explicit operator authorization.

This probe **does not** validate OAuth, HTTP Streamable transport, multi-round-trip requests, all MCP primitives, schema semantics or every protocol extension. It does not run arbitrary unconfigured commands: the operator supplies an existing MCP configuration with one named stdio server. That process can have its own side effects on startup; use only trusted fixtures or sandboxed clients.

### Examples

```bash
faraday compat probe --config .mcp.json --server local-filesystem --protocol modern --out evidence.json
faraday compat probe --config .mcp.json --server legacy-demo --protocol legacy
faraday compat probe --config .mcp.json --server local-filesystem --call-tool list_allowed_directories --allow-call
```

Never place secrets in MCP server names or tool names; the report deliberately discards server responses and tool arguments. Report files use owner-only permissions where the operating system supports Unix modes.

## External interoperability, verified in GitHub Actions

A dedicated CI job on Node 24 installs pinned **official** server packages into an isolated test prefix:

- `@modelcontextprotocol/server-filesystem@2.0.1` scoped to a fresh temporary directory
- `@modelcontextprotocol/server-everything@2.0.1`

Each server is probed in a fresh process with **both legacy and modern protocol versions**, and only an explicitly chosen filesystem read-only tool is called. Versions are pinned to upstream security-fixed releases. The job checks tool visibility and elapsed times without copying tool payloads to logs. No AI model or token is required.

## Cold install / rollback matrix

The workflow `mcp-live-interop.yml` also exercises Linux, macOS and Windows: `npm pack` -> local offline installation in a fresh prefix -> `faraday init` -> reversible `install` -> `uninstall` -> `doctor`. It validates equality of the original server entry and stores a runtime duration. It does not edit actual IDE profiles and does not measure human onboarding.

**Exit gate:** claim only the environments whose GitHub Actions jobs pass. On failures retain E05/E06 as partially verified and publish the precise limitation.

## External CI evidence — 2026-10-29

[GitHub Actions run 40857495831](https://github.com/jandromani/faraday/actions/runs/40857495831): **4/4 jobs passed**. The official read-only MCP `stdio` probe observed:

| Official pinned package | MCP 2026-07-28 | MCP 2025-11-25 |
| --- | ---: | ---: |
| Filesystem 2.0.1 | 14 tools | 14 tools |
| Everything 2.0.1 | 22 tools | 16 tools |

The different per-era tool counts were observed, not assumed. Filesystem `list_allowed_directories` was called with an explicit read-only opt-in; **no writes** were requested by the probe.

| Hosted OS | Node.js | Cold install, rollback and doctor |
| --- | --- | ---: |
| Linux | 24.22.1 | 1,535 ms |
| macOS | 24.21.0 | 2,349 ms |
| Windows | 24.22.1 | 5,265 ms |

These timings apply to the isolated runner fixture only; they are **not a human onboarding SLA**. The probe did not test HTTP/OAuth, prompt/resource conformance, all transports or security of arbitrary untrusted MCP servers. **E05/E06 subdeliverables passed; enterprise epics remain partially complete.**

## References

- Official MCP specification 2026-07-28: https://modelcontextprotocol.io/specification/2026-07-28
- Official MCP servers: https://github.com/modelcontextprotocol/servers
