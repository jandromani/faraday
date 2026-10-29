"""Real-SDK smoke tests. No models, keys, network calls or external tools invoked.

Usage: PYTHONPATH=python python3 python/tests/sdk_smoke.py langgraph|crewai|openai
"""
import asyncio
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import TypedDict

from faraday_adapters import (Recorder, wrap_node, make_tool_hooks,
                              register_tool_hooks, make_function_tool, make_run_hooks)


def main(which):
    with tempfile.TemporaryDirectory() as tmp:
        recorder = Recorder(Path(tmp) / 'trace.jsonl')
        if which == 'langgraph':
            from langgraph.graph import StateGraph, START, END
            class State(TypedDict):
                n: int
            graph = StateGraph(State)
            graph.add_node('increment', wrap_node(lambda state: {'n': state['n'] + 1},
                                                  name='increment', recorder=recorder))
            graph.add_edge(START,'increment');graph.add_edge('increment',END)
            result=graph.compile().invoke({'n':1})
            assert result['n']==2, result
        elif which == 'openai':
            from agents import FunctionTool
            tool=make_function_tool(lambda text: text.upper(), name='uppercase',
                                    params_json_schema={'type':'object','properties':{'text':{'type':'string'}},'required':['text'],'additionalProperties':False},
                                    recorder=recorder, allowed_tools={'uppercase'})
            assert isinstance(tool, FunctionTool)
            assert asyncio.run(tool.on_invoke_tool(None, '{"text":"hi"}')) == 'HI'
            hooks=make_run_hooks(recorder=recorder)
            asyncio.run(hooks.on_agent_start(None,SimpleNamespace(name='dummy-agent')))
        elif which == 'crewai':
            from crewai.hooks import get_before_tool_call_hooks, get_after_tool_call_hooks
            unregister=register_tool_hooks(recorder=recorder,allowed_tools={'lookup'})
            try:
                ctx=SimpleNamespace(tool_name='lookup', agent=SimpleNamespace(role='dummy'), tool_input={'key':'private'}, tool_result='sensitive')
                for hook in get_before_tool_call_hooks():
                    hook(ctx)
                for hook in get_after_tool_call_hooks():
                    hook(ctx)
            finally:
                unregister()
        else:
            raise SystemExit('Choose langgraph, openai or crewai')
        events=[json.loads(line) for line in (Path(tmp)/'trace.jsonl').read_text().splitlines()]
        assert events and all(e['version']==1 for e in events), events
        assert 'private' not in repr(events) and 'sensitive' not in repr(events)
        print(json.dumps({'sdk':which,'ok':True,'metadataEvents':len(events),'realSDKImported':True}))

if __name__=='__main__':main(sys.argv[1])
