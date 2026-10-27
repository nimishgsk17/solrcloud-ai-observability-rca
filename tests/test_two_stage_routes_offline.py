"""Offline routing tests using a tiny TEST-ONLY LangGraph emulator.

These tests exercise project node functions, transitions and outcomes; they do
NOT claim to replace testing the real langgraph package on the user's machine.
"""
import sys
import types
import unittest
from unittest.mock import patch
from tests.test_project import run_case
from agent import investigate, practice_model

START = '__start__'
END = '__end__'

class TestOnlyStateGraph:
    def __init__(self, state_schema):
        self.nodes={};self.edges={};self.conditions={}
    def add_node(self, name, func): self.nodes[name]=func
    def add_edge(self, a, b): self.edges[a]=b
    def add_conditional_edges(self,a,func,mapping): self.conditions[a]=(func,mapping)
    def compile(self): return self
    def invoke(self, data):
        state=dict(data)
        node=self.edges[START]
        for _ in range(20):
            if node == END: return state
            new = self.nodes[node](state)
            state.update(new)
            if node in self.conditions:
                fn,mapping=self.conditions[node]
                node=mapping[fn(state)]
            else: node=self.edges[node]
        raise AssertionError('Possible unbounded loop')

class TwoStageRoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report,_=run_case('gc')
        cls.incident=cls.report['incidents'][0]

    def run_graph(self, model, **options):
        module=types.ModuleType('langgraph')
        graph=types.ModuleType('langgraph.graph')
        graph.StateGraph=TestOnlyStateGraph
        graph.START=START
        graph.END=END
        module.graph=graph
        with patch.dict(sys.modules, {'langgraph':module,'langgraph.graph':graph}):
            return investigate(self.incident,self.report['events'],model,**options)

    def test_two_model_stages_and_diagnostic(self):
        requests=[]
        def model(dossier, feedback):
            requests.append(dossier['stage'])
            return practice_model(dossier,feedback)
        result=self.run_graph(model)
        self.assertEqual(requests,['triage','final'])
        self.assertEqual(result['report']['status'],'AI_PROPOSAL_REQUIRES_HUMAN_REVIEW')
        self.assertEqual(result['diagnostic']['check'],'gc_query_timeline')
        self.assertTrue(any('read-only' in s for s in result['graph_steps']))

    def test_zero_diagnostic_rounds(self):
        r=self.run_graph(practice_model,max_diagnostic_rounds=0)
        self.assertEqual(r['diagnostic']['check'],'none')
        self.assertEqual(r['report']['status'],'AI_PROPOSAL_REQUIRES_HUMAN_REVIEW')

    def test_initial_invalid_citations_fallback(self):
        counts=[]
        def bad(dossier, feedback):
            counts.append(dossier['stage'])
            answer=practice_model(dossier,feedback)
            answer['evidence_ids']=['FAKE']
            return answer
        r=self.run_graph(bad,retries_per_stage=1)
        self.assertEqual(counts,['triage','triage'])
        self.assertEqual(r['report']['status'],'RULE_BASED_FALLBACK')

    def test_final_invalid_citations_fallback(self):
        counts=[]
        def bad(dossier, feedback):
            counts.append(dossier['stage'])
            answer=practice_model(dossier,feedback)
            if dossier['stage']=='final': answer['hypotheses'][0]['evidence_ids']=['FAKE']
            return answer
        r=self.run_graph(bad,retries_per_stage=1)
        self.assertEqual(counts,['triage','final','final'])
        self.assertEqual(r['report']['status'],'RULE_BASED_FALLBACK')

if __name__=='__main__':unittest.main()
