# MCP compatibility matrix — FARADAY v0.8

This document separates configured support from tested runtime behavior.

| Connection | Config discovery | Instrumentation | Verified fixture | External conformance |
| --- | --- | --- | --- | --- |
| Claude Code `.mcp.json` stdio | Yes | stdio wrapper | Synthetic | Untested |
| Cursor `.cursor/mcp.json` stdio | Yes | stdio wrapper | Synthetic | Untested |
| VS Code `.vscode/mcp.json` stdio | Yes | stdio wrapper | Synthetic | Untested |
| Streamable HTTP server configured in these clients | Yes | stdio-to-HTTP bridge | JSON + SSE local | Untested |
| Legacy HTTP + SSE (`type=sse`) | Yes | No | No | Unsupported |
| Direct framework HTTP/tool APIs | No | No | No | Unsupported |

MCP specification: https://modelcontextprotocol.io/specification/2026-07-28

Version `2026-07-28` differs from earlier transport: stateless request metadata, no protocol-level initialize/session, MRTR extensions, and request-scoped SSE. Existing bridge supports a subset and legacy compatibility; it does not claim full conformance. `faraday compat --root .` reports configuration inventory and `verifiedLive=0` intentionally.

The local [bridge tests](../tests/http-bridge.test.js) cover JSON and request-scoped SSE, fragmented UTF-8/CRLF, missing or duplicate terminal responses, response IDs, negotiated legacy versions, HTTP 202 and correlated structured HTTP errors without retry. They use synthetic endpoints and do not establish interoperability with an independent HTTP client or server. The bridge does not implement full version negotiation, OAuth discovery/refresh, MRTR interaction handling, long-lived subscriptions or legacy SSE resumption; `x-mcp-header` validation is incomplete. Earlier official server evidence in [V0992](V0992_LIVE_MCP_INTEROP.md) is stdio-only and predates the Windows install restriction.

## Local official-client evidence

On Windows x64, Node 24.22.0, the official JavaScript SDK client 1.32.2 connected through FARADAY's stdio proxy to official filesystem server 2.0.1. The client negotiated MCP 2025-11-25, listed 14 tools and called `list_allowed_directories` against a temporary directory. The proxy recorded that tool's contract and successful response. This used an explicitly launched proxy, not automatic installation, and did not verify an IDE client, HTTP transport, write calls or full conformance. The proposed CI matrix runs the same check on Windows, macOS and Linux; it has not been run as part of this local change. The [smoke script](../scripts/real-mcp-client-smoke.mjs) requires those pinned packages under `FARADAY_MCP_FIXTURES` and never outputs tool results.

The synthetic stdio probe tests also cover a repeated cursor, malformed tool list, server exit and an unrelated response ID causing timeout. These are failure fixtures, not findings about the official SDK or server.

Before declaring an external client verified: record client version, OS, actual client workflow, tool listing, tool invocation, schema capture, receipt of response, uninstall, consent, error cases and references to tests/results. No credentials should appear in evidence.

## v0.98: Python adapter prototypes

Three **opt-in** integrations exist for LangGraph `StateGraph` nodes, CrewAI global tool hooks and OpenAI Agents SDK `FunctionTool`/`RunHooks`. Their dummy integration tests do not require provider credentials; real framework SDK smoke tests are separate, and do not establish conformance of a full agent workflow. See [V098_FRAMEWORK_ADAPTERS.md](V098_FRAMEWORK_ADAPTERS.md).
