# ADR-003 — OWASP Agentic, OWASP ACS and OpenTelemetry interoperability

**Decision:** create versioned control mappings and privacy-first telemetry, without claiming any standard's certification.

1. Map OWASP Agentic Top 10 ASI01–ASI10 to existing FARADAY modules/tests with residual gaps. `CONTROL_CROSSWALK_V1.json` lists every risk as **partial**. Passing a mapped unit test is NOT equivalent to mitigating the associated risk fully.
2. Treat the OWASP **Agent Control Standard** (ACS, launched September 2026) as a future portable hook/Guardian integration contract. FARADAY does **not** claim to implement ACS today. It is distinct from Microsoft's similarly named Agent Control Specification.
3. Introduce `lib/otel-mcp.js`, a minimal metadata-only OTel-compatible **span projection**. It emits `mcp.method.name`, and for tool calls `gen_ai.operation.name=execute_tool`. Raw tool names are fingerprinted and no prompts, raw arguments, outputs, bearer tokens or URLs are projected. This is **not a complete OpenTelemetry SDK, OTLP exporter or spec conformance implementation**; conventions are still in development.

Next: verify traceparent context propagation, sampling, consent, telemetry retention and security under untrusted collector endpoints; test with a real OTel Collector and viewer.

References:
- https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- https://genai.owasp.org/resource/agent-control-standard-acs/
- https://genai-security-project.github.io/agent-control-standard/docs/acs/
- https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/mcp.md
