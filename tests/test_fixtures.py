import tempfile
import unittest
from pathlib import Path

from auditor.coverage import AREAS, Coverage
from fixture_cases import CASES
from scripts.evaluate_fixtures import make_fixture, metrics, score
from tools import InspectionTools


class FixtureTests(unittest.TestCase):
    def test_corpus_is_readable_and_supports_all_nine_areas(self):
        for name, case in CASES.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as work:
                root = Path(work) / 'repository'
                make_fixture(root, case)
                tools, coverage = InspectionTools(root), Coverage()
                listing = tools.execute('list_files', {})
                coverage.observe('listing', 'list_files', {}, listing, 1)
                refs = []
                for index, path in enumerate(listing['files']):
                    call_id = str(index)
                    result = tools.execute('read_file', {'path': path})
                    self.assertNotIn('error', result)
                    coverage.observe(call_id, 'read_file', {'path': path}, result, 1)
                    refs.append(call_id)
                coverage.record([{'area': area, 'status': 'checked', 'summary': 'Fixture content inspected', 'evidence_calls': refs}
                                 for area in AREAS], 2)
                coverage.assert_ready()

    def test_healthy_library_uses_acceptable_alternatives(self):
        files = CASES['healthy']['files']
        self.assertNotIn('requirements.txt', files)
        self.assertNotIn('poetry.lock', files)
        self.assertNotIn('.ruff.toml', files)
        self.assertIn('[tool.ruff]', files['pyproject.toml'])
        self.assertIn('ruff check', files['.github/workflows/ci.yml'])
        triage = files['.github/workflows/triage.yml']
        self.assertIn('pull_request_target', triage)
        self.assertNotIn('actions/checkout', triage)
        self.assertNotIn('pull_request.head', triage)

    def test_evaluator_does_not_double_count_duplicate_findings(self):
        finding = {'file': 'pyproject.toml', 'description': 'Conflicting versions', 'evidence': 'Requests versions differ'}
        result = score(CASES['obvious'], {'violations': [finding, finding]})
        self.assertEqual(result['matched'], ['dependency-conflict'])
        self.assertEqual(len(result['unexpected_findings_for_review']), 1)

    def test_evaluator_flags_unsupported_critical_severity(self):
        finding = {'file': '.github/workflows/ci.yml', 'description': 'Tests skipped',
                   'evidence': 'echo Tests skipped', 'severity': 'critical'}
        result = score(CASES['obvious'], {'violations': [finding]})
        self.assertEqual(result['severity_issues'], [{'id': 'tests-skipped', 'severity': 'critical'}])

    def test_metrics_use_assignment_precision_and_recall_formulas(self):
        result = metrics({'case': {'report': {'violations': [{}, {}]}, 'matched': ['one'], 'missed': ['two', 'three']}})
        self.assertEqual(result['precision'], 0.5)
        self.assertAlmostEqual(result['recall'], 1 / 3)
        self.assertIsNone(metrics({})['precision'])
        self.assertIsNone(metrics({})['recall'])
