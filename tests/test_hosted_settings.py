"""Offline smoke tests of prompt budgeting and OpenAI-compatible request params."""
import io
import json
import unittest
from unittest.mock import patch
from agent import ask_model, budgeted_evidence, estimate_input_tokens
from tests.test_project import run_case


class DummyResponse:
    def __init__(self, data):
        self.stream = io.BytesIO(json.dumps(data).encode('utf8'))
    def __enter__(self):
        return self.stream
    def __exit__(self, *args):
        self.stream.close()


class HostedSettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report, _ = run_case('gc')
        cls.incident = cls.report['incidents'][0]

    def test_dossier_selected_and_bounded(self):
        d = budgeted_evidence(self.incident, self.report['events'],
                              evidence_limit=5, input_budget_tokens=6144,
                              context_window_tokens=131072, max_output_tokens=1152)
        self.assertLessEqual(len(d['observations']), 5)
        self.assertLessEqual(estimate_input_tokens(d), 6144)

    def test_small_context_rejects_too_long_output(self):
        with self.assertRaisesRegex(ValueError, 'Context capacity'):
            budgeted_evidence(self.incident, self.report['events'],
                              context_window_tokens=2048, max_output_tokens=1900)

    def test_request_headers_and_params(self):
        d = budgeted_evidence(self.incident, self.report['events'], evidence_limit=4)
        captured = {}
        def fake_urlopen(request, timeout):
            captured['url'] = request.full_url
            captured['timeout'] = timeout
            captured['body'] = json.loads(request.data)
            captured['auth'] = request.headers['Authorization']
            return DummyResponse({'choices': [{'message': {'content': '{"hypotheses": []}'}}],
                                  'usage': {'prompt_tokens': 123, 'completion_tokens': 42}})
        with patch('agent.urllib.request.urlopen', side_effect=fake_urlopen):
            response = ask_model(d, '', base_url='https://api.groq.com/openai/v1',
                                 model='openai/gpt-oss-120b', api_key='test-token',
                                 timeout=75, max_output_tokens=1152, temperature=0.1,
                                 json_mode=True, reasoning_effort="low")
        self.assertEqual(captured['url'], 'https://api.groq.com/openai/v1/chat/completions')
        self.assertEqual(captured['timeout'], 75)
        self.assertEqual(captured['body']['max_completion_tokens'], 1152)
        self.assertEqual(captured['body']['temperature'], 0.1)
        self.assertEqual(captured['body']['reasoning_effort'], 'low')
        self.assertEqual(captured['body']['response_format'], {'type': 'json_object'})
        self.assertEqual(captured['auth'], 'Bearer test-token')
        self.assertEqual(response['_api_usage']['prompt_tokens'], 123)

    def test_reasoning_model_omits_temperature(self):
        d = budgeted_evidence(self.incident, self.report['events'], evidence_limit=2)
        body = {}
        def fake_urlopen(request, timeout):
            body.update(json.loads(request.data))
            return DummyResponse({'choices': [{'message': {'content': '{}'}}]})
        with patch('agent.urllib.request.urlopen', side_effect=fake_urlopen):
            ask_model(d, '', base_url='https://api.openai.com/v1',
                      model='gpt-6-luna', api_key='fake', max_output_tokens=1152)
        self.assertEqual(body['max_completion_tokens'], 1152)
        self.assertNotIn('temperature', body)


if __name__ == '__main__':
    unittest.main()
