import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess

from auditor.coverage import AREAS
from auditor.repository import AuditError
from scripts.evaluate_public import audit, verify_artifacts


URL = 'https://github.com/example/public-test'


class PublicEvaluationTests(unittest.TestCase):
    def artifacts(self, root):
        report = {'repository': URL, 'violations': []}
        events = [
            {'event': 'repository_snapshot', 'commit': 'abc123'},
            {'event': 'tool_result', 'turn': 1, 'name': 'list_files', 'call_id': 'L',
             'result': {'files': ['README.md'], 'truncated': False}},
            {'event': 'tool_result', 'turn': 2, 'name': 'read_file', 'call_id': 'R',
             'result': {'path': 'README.md', 'lines': [{'line': 1, 'text': '# Demo'}]}},
            {'event': 'coverage', 'turn': 3, 'assessments': {area: {'status': 'checked', 'evidence_calls': ['R']} for area in AREAS}},
            {'event': 'completed', 'turn': 4, 'report': report},
        ]
        report_path, trace_path = root / 'report.json', root / 'trace.jsonl'
        report_path.write_text(json.dumps(report))
        trace_path.write_text('\n'.join(json.dumps(event) for event in events))
        return report_path, trace_path, events

    def test_valid_completion_has_coverage_and_provenance(self):
        with tempfile.TemporaryDirectory() as work:
            report, trace, _ = self.artifacts(Path(work))
            result = verify_artifacts(URL, report, trace)
            self.assertEqual(result['target_commit'], 'abc123')
            self.assertEqual(result['finding_count'], 0)
            self.assertEqual(result['model_turns'], 4)

    def test_fabricated_evidence_or_mismatched_report_is_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            report, trace, events = self.artifacts(Path(work))
            events[3]['assessments']['ci']['evidence_calls'] = ['invented']
            trace.write_text('\n'.join(json.dumps(event) for event in events))
            with self.assertRaises(AuditError):
                verify_artifacts(URL, report, trace)
            report, trace, _ = self.artifacts(Path(work))
            report.write_text(json.dumps({'repository': URL, 'violations': [None]}))
            with self.assertRaises(AuditError):
                verify_artifacts(URL, report, trace)

    def test_nonzero_cli_exit_is_preserved_without_claiming_completion(self):
        with tempfile.TemporaryDirectory() as work:
            process = subprocess.CompletedProcess([], 1, '', 'Useful error')
            with patch('scripts.evaluate_public.subprocess.run', return_value=process):
                result = audit(URL, Path(work), 10)
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['exit_code'], 1)

    def test_wall_timeout_is_explicit(self):
        with tempfile.TemporaryDirectory() as work:
            with patch('scripts.evaluate_public.subprocess.run', side_effect=subprocess.TimeoutExpired('agent', 10)):
                result = audit(URL, Path(work), 10)
            self.assertEqual(result['status'], 'timed_out')
