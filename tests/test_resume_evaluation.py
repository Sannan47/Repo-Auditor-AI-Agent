import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from scripts.resume_evaluation import ReplayProvider, VerifiedTrace, replay_prefix
from auditor.repository import AuditError


class ResumeTests(unittest.TestCase):
    def decision(self, name):
        return {'event': 'decision', 'message': {'role': 'assistant', 'content': None,
                'tool_calls': [{'function': {'name': name, 'arguments': '{}'}}]}}

    def test_replays_only_through_first_submission_then_calls_live_provider(self):
        events = [self.decision('list_files'), self.decision('submit_report'), self.decision('submit_report')]
        saved = replay_prefix(events)
        self.assertEqual(len(saved), 2)
        live, trace = Mock(), Mock()
        live.complete.return_value = {'role': 'assistant', 'content': 'live'}
        provider = ReplayProvider(saved, live, trace)
        provider.complete([], [])['tool_calls'][0]['function']['name'] = 'changed'
        self.assertEqual(saved[0]['tool_calls'][0]['function']['name'], 'list_files')
        provider.complete([], [])
        self.assertEqual(provider.complete([], [])['content'], 'live')
        live.complete.assert_called_once()

    def test_changed_primary_observation_aborts_instead_of_reusing_it(self):
        original = [{'event': 'tool_result', 'call_id': 'c1', 'name': 'read_file', 'result': {'lines': ['original']}}]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'trace.jsonl'
            with VerifiedTrace(path, original) as trace:
                with self.assertRaisesRegex(AuditError, 'differs'):
                    trace.write('tool_result', call_id='c1', name='read_file', result={'lines': ['changed']})
            self.assertEqual(path.read_text(), '')

    def test_matching_primary_observation_is_actually_recorded(self):
        event = {'event': 'tool_result', 'call_id': 'c1', 'name': 'read_file', 'result': {'lines': ['same']}}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'trace.jsonl'
            with VerifiedTrace(path, [event]) as trace:
                trace.write('tool_result', call_id='c1', name='read_file', result={'lines': ['same']})
            self.assertEqual(json.loads(path.read_text()), event)
