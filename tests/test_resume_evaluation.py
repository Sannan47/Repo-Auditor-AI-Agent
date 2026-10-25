import json
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts.resume_evaluation import ReplayProvider, VerifiedTrace, replay_prefix, main
from auditor.provider import Settings
from auditor.prompts import REVIEW_SYSTEM_PROMPT
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

    def test_saved_accepted_candidate_is_preferred_over_failed_submissions(self):
        decisions = [dict(self.decision('list_files'), turn=1),
                     dict(self.decision('submit_report'), turn=2),
                     dict(self.decision('submit_report'), turn=3),
                     {'event': 'candidate_report', 'turn': 3},
                     dict(self.decision('submit_report'), turn=4)]
        self.assertEqual(len(replay_prefix(decisions)), 3)

    def test_independent_review_always_uses_live_provider_even_with_saved_decisions(self):
        live = Mock()
        live.complete.return_value = {'role': 'assistant', 'content': 'fresh review'}
        provider = ReplayProvider([self.decision('submit_report')['message']], live, Mock())
        result = provider.complete([{'role': 'system', 'content': REVIEW_SYSTEM_PROMPT}], [])
        self.assertEqual(result['content'], 'fresh review')
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

    def test_model_change_requires_explicit_flag_before_any_clone(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'old.jsonl'
            source.write_text('\n'.join(json.dumps(e) for e in [
                {'event': 'started', 'repository': 'https://github.com/example/demo', 'model': 'old-model'},
                {'event': 'repository_snapshot', 'commit': 'abc'}, self.decision('list_files')]))
            argv = ['resume', '--trace', str(source), '--output', str(Path(folder) / 'new.json')]
            with patch('sys.argv', argv), patch('dotenv.load_dotenv'), \
                 patch('scripts.resume_evaluation.Settings.from_environment', return_value=Settings('unit-test-key', 'new-model')), \
                 patch('scripts.resume_evaluation.clone_repository') as clone, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(), 1)
                clone.assert_not_called()

    def test_explicit_model_handoff_is_recorded_in_output_trace(self):
        with tempfile.TemporaryDirectory() as folder:
            source, output = Path(folder) / 'old.jsonl', Path(folder) / 'new.json'
            repository = 'https://github.com/example/demo'
            source.write_text('\n'.join(json.dumps(e) for e in [
                {'event': 'started', 'repository': repository, 'model': 'old-model'},
                {'event': 'repository_snapshot', 'commit': 'abc'}, self.decision('list_files')]))
            argv = ['resume', '--trace', str(source), '--output', str(output), '--allow-model-change']
            with patch('sys.argv', argv), patch('dotenv.load_dotenv'), \
                 patch('scripts.resume_evaluation.Settings.from_environment', return_value=Settings('unit-test-key', 'new-model')), \
                 patch('scripts.resume_evaluation.clone_repository'), \
                 patch('scripts.resume_evaluation.git_command', return_value='abc\n'), \
                 patch('scripts.resume_evaluation.OpenAICompatibleProvider'), \
                 patch('scripts.resume_evaluation.InspectionTools'), \
                 patch('scripts.resume_evaluation.run_agent', return_value={'repository': repository, 'violations': []}), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(), 0)
            events = [json.loads(line) for line in Path(str(output) + '.trace.jsonl').read_text().splitlines()]
            handoff = next(e for e in events if e['event'] == 'resumed_from')
            self.assertEqual(handoff['original_model'], 'old-model')
            self.assertEqual(handoff['continuation_model'], 'new-model')
