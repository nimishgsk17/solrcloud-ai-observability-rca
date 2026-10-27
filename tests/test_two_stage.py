"""Unit tests for two-stage RCA without a remote model or real Solr server."""
import copy
import json
import unittest
from unittest.mock import patch
from agent import (DIAGNOSTIC_LABELS, prepare_evidence, check_triage,
                   run_read_only_check, budgeted_evidence, prepare_final_dossier,
                   estimate_stage_tokens, practice_model, check_response, ask_model)
from tests.test_project import run_case
from tests.test_hosted_settings import DummyResponse


class TwoStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report, _ = run_case('gc')
        cls.incident = cls.report['incidents'][0]
        cls.evidence = budgeted_evidence(cls.incident, cls.report['events'],
                                         evidence_limit=12, input_budget_tokens=6144,
                                         context_window_tokens=131072, max_output_tokens=2048)
        cls.evidence['allowed_checks'] = list(DIAGNOSTIC_LABELS)
        cls.evidence['stage'] = 'triage'

    def test_mock_triage_requests_allowed_tool(self):
        proposal = practice_model(self.evidence, '')
        self.assertEqual(proposal['requested_check'], 'gc_query_timeline')
        self.assertEqual(check_triage(proposal, self.evidence), '')

    def test_triage_rejects_arbitrary_commands(self):
        proposal = practice_model(self.evidence, '')
        proposal['requested_check'] = 'powershell rm -r C:\\'
        self.assertIn('unapproved', check_triage(proposal, self.evidence))

    def test_triage_rejects_fake_evidence(self):
        proposal = practice_model(self.evidence, '')
        proposal['evidence_ids'] = ['invented']
        self.assertIn('invented', check_triage(proposal, self.evidence))

    def test_read_only_check_timeline(self):
        result = run_read_only_check('gc_query_timeline', self.incident,
                                     self.report['events'], window_minutes=6, max_examples=5)
        self.assertGreater(result['examined_events'], 0)
        self.assertTrue(result['minute_buckets'])
        self.assertLessEqual(len(result['observations']), 5)
        for e in result['observations']:
            self.assertIn(e['id'], {x['id'] for x in self.report['events']})

    def test_other_tools(self):
        for tool in DIAGNOSTIC_LABELS:
            with self.subTest(tool=tool):
                r = run_read_only_check(tool, self.incident, self.report['events'])
                self.assertEqual(r['check'], tool)
                self.assertIn('summary', r)

    def test_reject_illegal_tool_execution(self):
        with self.assertRaises(ValueError):
            run_read_only_check('shell', self.incident, self.report['events'])

    def test_second_dossier_fits_limit_and_has_real_evidence(self):
        first = practice_model(self.evidence, '')
        checked = run_read_only_check(first['requested_check'], self.incident,
                                      self.report['events'], max_examples=8)
        result = prepare_final_dossier(self.evidence, first, checked,
                 input_budget_tokens=6144, context_window_tokens=131072, max_output_tokens=2048)
        result['stage'] = 'final'
        self.assertLessEqual(estimate_stage_tokens(result, 'final'), 6144)
        self.assertEqual(result['additional_read_only_check']['check'], 'gc_query_timeline')
        self.assertEqual(check_response(practice_model(result, ''), result), '')

    def test_initial_and_final_json_prompts_are_distinct(self):
        bodies=[]
        def fake(req, timeout):
            b=json.loads(req.data)
            bodies.append(b)
            return DummyResponse({'choices':[{'message': {'content': '{}'}}]})
        with patch('agent.urllib.request.urlopen',side_effect=fake):
            ask_model(self.evidence, '', base_url='https://api.groq.com/openai/v1',
                      model='openai/gpt-oss-120b', stage='triage', top_p=.9,
                      json_mode=True)
            ask_model(self.evidence, '', base_url='https://api.groq.com/openai/v1',
                      model='openai/gpt-oss-120b', stage='final')
        self.assertIn('preliminary_hypothesis', bodies[0]['messages'][0]['content'])
        self.assertIn('manual_checks', bodies[1]['messages'][0]['content'])
        self.assertEqual(bodies[0]['top_p'], .9)
        self.assertEqual(bodies[0]['response_format'], {'type':'json_object'})

if __name__ == '__main__':
    unittest.main()
