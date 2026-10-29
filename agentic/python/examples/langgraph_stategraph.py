"""Use after pip install langgraph. This workflow makes no model requests."""
from typing import TypedDict
from langgraph.graph import StateGraph, START, END
from faraday_adapters import Recorder, wrap_node

class State(TypedDict):
    count: int

recorder=Recorder('.faraday/langgraph.jsonl')
graph=StateGraph(State)
graph.add_node('increment',wrap_node(lambda state:{'count':state['count']+1}, name='increment',recorder=recorder))
graph.add_edge(START,'increment');graph.add_edge('increment',END)
print(graph.compile().invoke({'count':0}))
