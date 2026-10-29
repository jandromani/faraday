"""OpenAI Agents SDK integration using public FunctionTool and RunHooks APIs."""
import asyncio
import json
from .core import Recorder, instrument


def make_function_tool(fn, *, name: str, params_json_schema: dict,
                       recorder: Recorder, description: str = 'Synthetic tool',
                       allowed_tools: set[str] | None = None, agent: str = 'agent'):
    """Create a FunctionTool whose execution (not just hooks) is instrumented.

    This covers only tools explicitly created through this helper. Hosted tools,
    direct API calls and handoffs are not thereby intercepted.
    """
    try:
        from agents import FunctionTool
    except ImportError as exc:
        raise ImportError('Install openai-agents to create FARADAY FunctionTool') from exc
    wrapped = instrument(fn, recorder=recorder, framework='openai-agents',
                         agent=agent, tool=name, allowed_tools=allowed_tools)

    async def invoke(context, args_json: str):
        if not isinstance(args_json, str) or len(args_json) > 65536:
            raise ValueError('Tool arguments exceed limit')
        arguments = json.loads(args_json)
        if not isinstance(arguments, dict):
            raise ValueError('Tool arguments must be an object')
        if asyncio.iscoroutinefunction(wrapped):
            value = await wrapped(**arguments)
        else:
            value = wrapped(**arguments)
        return value if isinstance(value, str) else json.dumps(value)
    return FunctionTool(name=name, description=description,
                        params_json_schema=params_json_schema, on_invoke_tool=invoke)


def make_run_hooks(*, recorder: Recorder):
    """Observe agent lifecycle using the public SDK RunHooks interface.

    Hooks are advisory; use make_function_tool for tool-local allowlists.
    """
    try:
        from agents import RunHooks
    except ImportError as exc:
        raise ImportError('Install openai-agents for FARADAY RunHooks') from exc
    class FaradayHooks(RunHooks):
        async def on_agent_start(self, context, agent):
            recorder.record('openai-agents', str(agent.name), 'lifecycle', 'agent_start', 'started')
        async def on_agent_end(self, context, agent, output):
            recorder.record('openai-agents', str(agent.name), 'lifecycle', 'agent_end', 'ok')
        async def on_tool_start(self, context, agent, tool):
            recorder.record('openai-agents', str(agent.name), str(tool.name), 'tool_call', 'started')
        async def on_tool_end(self, context, agent, tool, result):
            recorder.record('openai-agents', str(agent.name), str(tool.name), 'tool_call', 'ok')
    return FaradayHooks()
