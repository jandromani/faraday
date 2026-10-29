# FARADAY v0.98 — Framework Adapters (E07 partial)

**Status: experimental, opt-in, no monkey-patching, no mandatory security enforcement.**

FARADAY provides three adapters in `agentic/python/faraday_adapters`:

| Framework | Public integration surface | Validation | Important limitation |
| --- | --- | --- | --- |
| LangGraph | `wrap_node` for `StateGraph.add_node`; `wrap_tool` around explicitly selected Python callables | Offline dummy nodes, sync/async, errors, optional local allowlist | Does not intercept all other nodes, tools, compiled graphs or raw HTTP |
| CrewAI | `register_tool_hooks` via `crewai.hooks` before/after tool calls | Mock-hook registration and denied/allowed cases | Global hooks only cover SDK-mediated tools; errors/denials can lead to after-hook, recorded as `unverified` |
| OpenAI Agents SDK | `FunctionTool` via `make_function_tool`, lifecycle via `RunHooks` | Mock-SDK execution with no inference; optional real-SDK smoke | Explicit FunctionTools only; hosted tools, other FunctionTools and handoffs outside this helper not governed; tool-end hook records `unverified` |

## Quickstart

```bash
cd agentic
# No dependencies required for adapter import or unit tests:
PYTHONPATH=python python3 -m unittest discover -s python/tests -v

# With the SDK of your choosing installed:
PYTHONPATH=python python3 python/examples/langgraph_stategraph.py
PYTHONPATH=python python3 python/examples/openai_functiontool.py
PYTHONPATH=python python3 python/examples/crewai_hooks.py

# After an instrumented run, ingest locally into SQLite Graph:
node bin/faraday.js adapters ingest --file .faraday/langgraph.jsonl --db .faraday/graph.sqlite
node bin/faraday.js graph --db .faraday/graph.sqlite --format mermaid
```

**Privacy:** only strict schema-v1 metadata events are written; agent/tool names are SHA-256 pseudonyms by default; no prompts, user input, tool arguments, results, URLs or exception text are exported. Identifiers are pseudonyms, not guaranteed anonymous if their original names are guessable. Logs and database are private files. A stable `salt` may be configured on the recorder to reduce offline dictionary matching.

**Scope:** This is *instrumentation* with an optional local allowlist, **not a mandatory boundary**. For privileged tools, require the Authority Gateway + network and credential isolation regardless of framework hooks. A developer can still bypass these wrappers by calling the underlying Python function directly.

**Version compatibility:** SDK APIs may change; the optional `python/tests/sdk_smoke.py` exercises real installed SDK objects without an LLM, external API call or credentials. Testing dummy/SDK constructors is **not** end-to-end agent interoperability certification. Record SDK versions and fixture outcomes before marking external compatibility verified.

**Ingestion safety:** max 8 MiB / 10,000 rows / 4 KiB per row; fixed keys only; opaque identifiers only; symlink rejection; atomic SQLite ingest and digest-based deduplication. Duplicate whole-file imports are skipped; different files containing overlapping rows may result in duplicate observations.

New imports distinguish denied, started and unverified events from reported completed calls in graph relations and counters. These labels reflect adapter reports, not independent proof of authorization, delegation or external effects; existing graph rows are not migrated. `graph clear` also clears the import index so the same trace can be imported again. Recorder failure after a wrapped function has returned can still make the caller see an exception after an external side effect; `on_error='drop'` avoids that exception but may lose evidence. Neither mode guarantees exactly-once execution.

**References:** [LangGraph StateGraph](https://docs.langchain.com/oss/python/langgraph/graph-api), [CrewAI Tool Hooks](https://docs.crewai.com/en/learn/tool-hooks), [OpenAI Agents SDK Tools](https://openai.github.io/openai-agents-python/tools/).
