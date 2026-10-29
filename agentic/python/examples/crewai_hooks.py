"""Use after pip install crewai. Register before creating/running a crew."""
from faraday_adapters import Recorder, register_tool_hooks
recorder=Recorder('.faraday/crewai.jsonl')
unregister=register_tool_hooks(recorder=recorder,allowed_tools={'read_document'})
# Create/run your Crew(...) here. Calls to other tool names are denied by
# this CrewAI hook, but direct Python/API calls can still bypass the hook.
# Finally invoke unregister() to restore prior hook state.
print('CrewAI hooks installed. Call unregister() when your run ends.')
