"""CrewAI tool hooks. Explicit registration; no monkey patching."""
from .core import Recorder


def make_tool_hooks(*, recorder: Recorder, allowed_tools: set[str] | None = None):
    """Return (before, after) suitable for crewai.hooks registration.

    Global hooks may not cover direct Python calls or SDK-specific execution paths.
    """
    def before(context):
        name = context.tool_name
        who = getattr(getattr(context, 'agent', None), 'role', None) or 'crew'
        if allowed_tools is not None and name not in allowed_tools:
            recorder.record('crewai', str(who), str(name), 'tool_call', 'denied')
            return False
        return None

    def after(context):
        who = getattr(getattr(context, 'agent', None), 'role', None) or 'crew'
        # This hook cannot reliably distinguish tool errors or blocked results.
        recorder.record('crewai', str(who), str(context.tool_name), 'tool_call', 'unverified')
        return None
    return before, after


def register_tool_hooks(*, recorder: Recorder, allowed_tools: set[str] | None = None):
    try:
        from crewai.hooks import (register_before_tool_call_hook, register_after_tool_call_hook,
                                  unregister_before_tool_call_hook, unregister_after_tool_call_hook)
    except ImportError as exc:
        raise ImportError('Install crewai to register FARADAY CrewAI hooks') from exc
    before, after = make_tool_hooks(recorder=recorder, allowed_tools=allowed_tools)
    register_before_tool_call_hook(before)
    register_after_tool_call_hook(after)

    def unregister():
        unregister_before_tool_call_hook(before)
        unregister_after_tool_call_hook(after)
    return unregister
