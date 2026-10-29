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

Before declaring an external client verified: record client version, OS, actual client workflow, tool listing, tool invocation, schema capture, receipt of response, uninstall, consent, error cases and references to tests/results. No credentials should appear in evidence.

## v0.98: Python adapter prototypes

Three **opt-in** integrations exist for LangGraph `StateGraph` nodes, CrewAI global tool hooks and OpenAI Agents SDK `FunctionTool`/`RunHooks`. Their dummy integration tests do not require provider credentials; real framework SDK smoke tests are separate, and do not establish conformance of a full agent workflow. See [V098_FRAMEWORK_ADAPTERS.md](V098_FRAMEWORK_ADAPTERS.md).
