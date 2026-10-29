"""Use after pip install openai-agents. The tool executes locally; no model needed."""
import asyncio
from faraday_adapters import Recorder, make_function_tool
recorder=Recorder('.faraday/openai.jsonl')

def uppercase(text: str):return text.upper()

tool=make_function_tool(uppercase,name='uppercase',
                        params_json_schema={'type':'object','properties':{'text':{'type':'string'}},'required':['text'],'additionalProperties':False},
                        recorder=recorder,allowed_tools={'uppercase'})
print(asyncio.run(tool.on_invoke_tool(None,'{"text":"hello"}')))
