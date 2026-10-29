"""Explicit wrappers for LangGraph StateGraph.add_node and tool functions."""
from .core import Recorder, instrument


def wrap_node(fn, *, name: str, recorder: Recorder, agent: str = 'graph'):
    """Pass returned function to StateGraph.add_node(name, wrap_node(...))."""
    return instrument(fn, recorder=recorder, framework='langgraph', agent=agent,
                      tool=name, kind='node_call')


def wrap_tool(fn, *, name: str, recorder: Recorder, agent: str = 'graph',
              allowed_tools: set[str] | None = None):
    """Wrap Python callable *before* exposing it as a LangChain tool."""
    return instrument(fn, recorder=recorder, framework='langgraph', agent=agent,
                      tool=name, allowed_tools=allowed_tools)
