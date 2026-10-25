import subprocess
import unittest

from auditor.coverage import AREAS, Coverage
from auditor.repository import AuditError
from test_tools import RepositoryFixture


class CoverageTests(RepositoryFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        (self.root / 'requirements.txt').write_text('requests==2.32.4\n')
        (self.root / 'pyproject.toml').write_text('[project]\ndependencies=["requests==2.32.4"]\n')
        folder = self.root / '.github/workflows'
        folder.mkdir(parents=True)
        (folder / 'ci.yml').write_text('on: [push, pull_request]\njobs: {}\n')
        subprocess.run(['git', '-C', str(self.root), 'add', '.'], check=True)
        self.coverage = Coverage()

    def observe(self, name, args, call_id, turn=1):
        result = self.tools.execute(name, args)
        self.coverage.observe(call_id, name, args, result, turn)

    def assessment(self, area, refs, status='checked'):
        return {'area': area, 'status': status, 'summary': 'Inspected relevant context and alternatives', 'evidence_calls': refs}

    def test_listing_and_negative_search_are_insufficient(self):
        self.observe('list_files', {}, 'listing')
        self.observe('search_code', {'pattern': 'not-found'}, 'search')
        with self.assertRaises(AuditError):
            self.coverage.record([self.assessment('dependency_management', ['listing', 'search'])], 2)

    def test_manifests_require_content_and_consistency_inspection(self):
        self.observe('list_files', {}, 'listing')
        self.observe('read_file', {'path': 'requirements.txt'}, 'requirements')
        with self.assertRaises(AuditError):
            self.coverage.record([self.assessment('dependency_management', ['requirements'])], 2)
        self.observe('read_file', {'path': 'pyproject.toml'}, 'project')
        self.coverage.record([self.assessment('dependency_management', ['requirements', 'project'])], 2)

    def test_cannot_cite_unknown_or_uninterpreted_results(self):
        self.observe('list_files', {}, 'listing')
        self.observe('read_file', {'path': '.github/workflows/ci.yml'}, 'ci', turn=2)
        for refs in (['imaginary'], ['ci']):
            with self.assertRaises(AuditError):
                self.coverage.record([self.assessment('ci', refs)], 2)

    def test_present_workflow_cannot_be_declared_inapplicable(self):
        self.observe('list_files', {}, 'listing')
        self.observe('read_file', {'path': 'README.md'}, 'readme')
        with self.assertRaises(AuditError):
            self.coverage.record([self.assessment('ci', ['readme'], 'not_applicable')], 2)

    def test_empty_page_is_not_content_inspection(self):
        self.observe('list_files', {}, 'listing')
        self.observe('read_file', {'path': 'README.md', 'start_line': 999, 'end_line': 999}, 'empty')
        with self.assertRaises(AuditError):
            self.coverage.record([self.assessment('repository_hygiene', ['empty'])], 2)

    def test_unavailable_requires_real_relevant_failure(self):
        self.observe('list_files', {}, 'listing')
        self.observe('read_file', {'path': 'README.md'}, 'readme')
        with self.assertRaises(AuditError):
            self.coverage.record([self.assessment('ci', ['readme'], 'unavailable')], 2)
        (self.root / '.github/workflows/ci.yml').write_bytes(b'x' * 512_001)
        self.observe('read_file', {'path': '.github/workflows/ci.yml'}, 'failed')
        self.coverage.record([self.assessment('ci', ['failed'], 'unavailable')], 2)

    def test_all_nine_areas_need_assessments(self):
        self.observe('list_files', {}, 'listing')
        for number, path in enumerate(('README.md', 'config.py', 'requirements.txt', 'pyproject.toml', '.github/workflows/ci.yml')):
            self.observe('read_file', {'path': path}, str(number))
        self.coverage.record([self.assessment(area, [str(n) for n in range(5)]) for area in AREAS[:-1]], 2)
        with self.assertRaises(AuditError):
            self.coverage.assert_ready()
        self.coverage.record([self.assessment(AREAS[-1], [str(n) for n in range(5)])], 2)
        self.coverage.assert_ready()

    def test_empty_repository_can_record_genuinely_absent_areas(self):
        empty = Coverage()
        empty.observe('listing', 'list_files', {}, {'files': [], 'truncated': False}, 1)
        empty.record([self.assessment(area, ['listing'], 'not_applicable') for area in AREAS], 2)
        empty.assert_ready()

    def test_valid_areas_persist_when_another_area_needs_more_evidence(self):
        self.observe('list_files', {}, 'listing')
        self.observe('read_file', {'path': 'README.md'}, 'readme')
        result = self.coverage.record([
            self.assessment('repository_hygiene', ['readme']),
            self.assessment('ci', []),
        ], 2)
        self.assertEqual(result['recorded'], ['repository_hygiene'])
        self.assertIn('ci', result['rejected'])
        self.assertNotIn('repository_hygiene', self.coverage.requirements())
        self.assertIn('ci', self.coverage.requirements())
        self.assertIn('evidence_calls is empty', result['rejected']['ci'])

    def test_planner_lists_only_unread_manifests_and_visible_evidence(self):
        self.observe('list_files', {}, 'listing')
        self.observe('read_file', {'path': 'requirements.txt'}, 'requirements')
        context = self.coverage.planning_context()
        self.assertNotIn('requirements.txt', context['unread_manifests'])
        self.assertIn('pyproject.toml', context['unread_manifests'])
        self.assertIn({'inspection_id': 'requirements', 'tool': 'read_file', 'path': 'requirements.txt',
                       'action': None, 'status': 'observed'}, context['evidence_index'])

    def test_missing_citation_is_distinguished_from_missing_inspection(self):
        self.observe('list_files', {}, 'listing')
        self.observe('read_file', {'path': 'requirements.txt'}, 'requirements')
        self.observe('read_file', {'path': 'pyproject.toml'}, 'project')
        with self.assertRaises(AuditError) as caught:
            self.coverage.record([self.assessment('dependency_management', ['requirements'])], 2)
        self.assertIn("'project': 'pyproject.toml'", str(caught.exception))
        self.assertIn('Actually unread: []', str(caught.exception))

    def test_one_unavailable_manifest_does_not_waive_unread_manifests(self):
        self.observe('list_files', {}, 'listing')
        self.observe('read_file', {'path': 'README.md'}, 'readme')
        (self.root / 'requirements.txt').write_bytes(b'x' * 512_001)
        self.observe('read_file', {'path': 'requirements.txt'}, 'failed')
        self.assertNotIn('dependency_management', self.coverage.eligible_areas())
        with self.assertRaises(AuditError):
            self.coverage.record([self.assessment('dependency_management', ['failed', 'readme'], 'unavailable')], 2)
