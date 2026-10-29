import asyncio
import json
import os
import pathlib
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))
from faraday_adapters import (Recorder, wrap_node, wrap_tool, make_tool_hooks,
                              register_tool_hooks, make_function_tool, make_run_hooks)

class AdapterTests(unittest.TestCase):
    def test_opaque_metadata_and_sync(self):
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp, 'events.jsonl')
            recorder = Recorder(path)
            fn = wrap_tool(lambda secret: {'secret': secret},name='private_tool',recorder=recorder,agent='name')
            self.assertEqual(fn('VERY_PRIVATE'),{'secret':'VERY_PRIVATE'})
            raw = path.read_text()
            self.assertNotIn('VERY_PRIVATE',raw)
            self.assertNotIn('private_tool',raw)
            self.assertNotIn('name',raw)
            self.assertEqual(json.loads(raw)['status'],'ok')
            if os.name!='nt':self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_langgraph_node_result_and_exception(self):
        r=Recorder()
        def good(state):return {'total':state['total']+1}
        self.assertEqual(wrap_node(good,name='inc',recorder=r)({'total':2}),{'total':3})
        def bad(state):raise ValueError('do not expose secret')
        with self.assertRaises(ValueError):wrap_node(bad,name='bad',recorder=r)({'secret':'do not expose secret'})
        self.assertEqual([e['status'] for e in r.events],['ok','error'])
        self.assertNotIn('do not expose secret',repr(r.events))

    def test_async_and_policy(self):
        r=Recorder();calls=[]
        async def run(value):calls.append(value);return value*2
        allowed=wrap_tool(run,name='read',recorder=r,allowed_tools={'read'})
        denied=wrap_tool(run,name='write',recorder=r,allowed_tools={'read'})
        self.assertEqual(asyncio.run(allowed(5)),10)
        with self.assertRaises(PermissionError):asyncio.run(denied(8))
        self.assertEqual(calls,[5]);self.assertEqual(r.events[-1]['status'],'denied')

    def test_crewai_pre_post_and_denied(self):
        r=Recorder()
        before,after=make_tool_hooks(recorder=r,allowed_tools={'read'})
        ctx=types.SimpleNamespace(tool_name='delete',agent=types.SimpleNamespace(role='admin'),tool_input={'password':'HIDDEN'})
        self.assertIs(before(ctx),False)
        self.assertIsNone(after(ctx))
        self.assertEqual([e['status'] for e in r.events],['denied','unverified'])
        self.assertNotIn('HIDDEN',repr(r.events))
        ctx.tool_name='read';self.assertIsNone(before(ctx))

    def test_crewai_registration_and_removal(self):
        calls=[]
        hooks=types.ModuleType('crewai.hooks')
        for name in ('register_before_tool_call_hook','register_after_tool_call_hook',
                     'unregister_before_tool_call_hook','unregister_after_tool_call_hook'):
            setattr(hooks,name,lambda h,n=name:calls.append((n,h)))
        with patch.dict(sys.modules,{'crewai':types.ModuleType('crewai'),'crewai.hooks':hooks}):
            unregister=register_tool_hooks(recorder=Recorder())
            unregister()
        self.assertEqual(len(calls),4)

    def test_openai_sdk_tool_and_hooks(self):
        class MockFunctionTool:
            def __init__(self,**kwargs):self.__dict__.update(kwargs)
        class MockRunHooks:pass
        fake=types.ModuleType('agents');fake.FunctionTool=MockFunctionTool;fake.RunHooks=MockRunHooks
        with patch.dict(sys.modules,{'agents':fake}):
            recorder=Recorder()
            def tool(text):return {'text':text}
            wrapped=make_function_tool(tool,name='echo',params_json_schema={'type':'object','properties':{'text':{'type':'string'}}},recorder=recorder,allowed_tools={'echo'})
            result=asyncio.run(wrapped.on_invoke_tool(None,json.dumps({'text':'SECRET'})))
            self.assertEqual(json.loads(result),{'text':'SECRET'})
            self.assertNotIn('SECRET',repr(recorder.events))
            denied=make_function_tool(tool,name='delete',params_json_schema={'type':'object'},recorder=recorder,allowed_tools={'echo'})
            with self.assertRaises(PermissionError):asyncio.run(denied.on_invoke_tool(None,'{"text":"SECRET"}'))
            hooks=make_run_hooks(recorder=recorder)
            agent=types.SimpleNamespace(name='worker');t=types.SimpleNamespace(name='echo')
            asyncio.run(hooks.on_agent_start(None,agent))
            asyncio.run(hooks.on_tool_start(None,agent,t))
            asyncio.run(hooks.on_tool_end(None,agent,t,'SECRET'))
            asyncio.run(hooks.on_agent_end(None,agent,'SECRET'))
            self.assertEqual(recorder.events[-1]['kind'],'agent_end')

    def test_recorder_file_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            target=pathlib.Path(temp,'target');target.write_text('secret')
            alias=pathlib.Path(temp,'alias');alias.symlink_to(target)
            with self.assertRaises((OSError,ValueError)):
                Recorder(alias).record('crewai','agent','tool','tool_call','ok')
            self.assertEqual(target.read_text(),'secret')

    def test_recorder_insecure_file_rejected(self):
        if os.name=='nt':self.skipTest('POSIX permissions only')
        with tempfile.TemporaryDirectory() as temp:
            target=pathlib.Path(temp,'events');target.write_text('');target.chmod(0o644)
            with self.assertRaises(ValueError):Recorder(target).record('crewai','a','b','tool_call','ok')

if __name__=='__main__':unittest.main()
