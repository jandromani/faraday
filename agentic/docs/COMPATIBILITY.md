# FARADAY v0.8 — MCP compatibility matrix

Compatibility report means **configuration discovery**, not certified runtime interoperability.

| Surface | Discovered | Instrumentation | Fixture-tested | External tested |
| --- | --- | --- | --- | --- |
| Claude Code .mcp.json stdio | Yes | stdio wrapper | Synthetic | No |
| Cursor .cursor/mcp.json stdio | Yes | stdio wrapper | Synthetic | No |
| VS Code .vscode/mcp.json stdio | Yes | stdio wrapper | Synthetic | No |
| Streamable HTTP configured in these clients | Yes | stdio-to-HTTP adapter | Local JSON/SSE | No |
| Legacy HTTP+SSE (`sse`) | Yes | No | No | No |
| Arbitrary framework direct HTTP APIs | No | No | No | No |

`faraday compat --root .` reports `verifiedLive: 0` until there are explicit live tests.

MCP 2026-07-28 introduced stateless request metadata and removed the core initialize/session handshake, while older versions used state. FARADAY's bridge has partial compatibility only: no blanket MRTR or extension conformance claims.

External validation requires recording OS, client/server version, protocol, request/response and errors (sanitized), contract capture, tool invocation, revert outcome and executable test references. Credentials are excluded.
