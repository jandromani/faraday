"""FARADAY opt-in, dependency-free framework adapters."""
from .core import Recorder, identity, instrument
from .langgraph import wrap_node, wrap_tool
from .crewai import make_tool_hooks, register_tool_hooks
from .openai_agents import make_function_tool, make_run_hooks
__all__ = ['Recorder', 'identity', 'instrument', 'wrap_node', 'wrap_tool',
           'make_tool_hooks', 'register_tool_hooks', 'make_function_tool', 'make_run_hooks']
