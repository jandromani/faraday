# R4 — Adapter interoperability and safe adoption

Status: **first implementation delivered; end-to-end acceptance pending**.

This iteration does not claim a previously approved R4 epic mapping. Scope is
incremental developer integration across LangGraph, CrewAI and OpenAI Agents.

## Security invariants
1. Adapter metadata is *never* a delegated credential or an execution grant.
2. An observed tool must not be silently promoted to authorized tool execution.
3. Capabilities are exact triples (tool, operation, resource); no wildcards.
4. A contract change that adds a capability requires independent Authority review.
5. Payloads, prompts, secrets, tokens and tool arguments must not enter metadata records.
6. R1–R3 gates remain independent and may not be bypassed by adapters.

## Delivered
- `lib/r4-adapter-contract.js`: strict schema, duplicate rejection, explicit
  observe-only contract, deterministic diff with review-needed signal.
- `tests/r4-adapter-contract.test.js`: negative behavior for privilege creep,
  wildcard resources, schema changes, unauthorized mode, duplicates.

## Not demonstrated
Real SDK conformance; live MCP calls through every framework; adapter compatibility
matrix with pinned framework/SDK versions; threat-model review of side-effect
semantics; offline packaging and installation UX; runnable three-framework examples.
Tests must execute in CI against the exact merged SHA before closure.
