from urllib.error import HTTPError
from urllib.request import Request
import unittest
from unittest.mock import patch

from auditor.github import GitHubOnlyRedirects, read_action_metadata
from auditor.repository import AuditError


class ActionMetadataTests(unittest.TestCase):
    def test_exact_ref_metadata_is_read_without_execution(self):
        text = 'inputs:\n  allow-unsafe-pr-checkout:\n    default: false\n'
        with patch('auditor.github._download', return_value=text) as download:
            result = read_action_metadata('actions/checkout@abc123')
        download.assert_called_once_with('https://raw.githubusercontent.com/actions/checkout/abc123/action.yml')
        self.assertEqual(result['ref'], 'abc123')
        self.assertIn('allow-unsafe-pr-checkout', str(result['lines']))

    def test_subdirectory_and_yaml_fallback(self):
        missing = HTTPError('unused', 404, 'missing', {}, None)
        with patch('auditor.github._download', side_effect=[missing, 'name: Metadata\n']) as download:
            result = read_action_metadata('owner/repo/sub@v1')
        self.assertEqual(result['path'], 'sub/action.yaml')
        self.assertEqual(download.call_count, 2)

    def test_invalid_refs_do_not_make_network_requests(self):
        with patch('auditor.github._download') as download:
            for value in ('file:///tmp/action', '../repo@main', 'owner/repo@../main', 'owner/repo@x?token=y', 'owner/repo/../other@v1'):
                with self.subTest(action=value), self.assertRaises(AuditError):
                    read_action_metadata(value)
        download.assert_not_called()

    def test_redirect_cannot_reach_another_host(self):
        handler = GitHubOnlyRedirects()
        with self.assertRaises(AuditError):
            handler.redirect_request(Request('https://raw.githubusercontent.com/a/b/main/action.yml'), None, 302, '', {}, 'http://127.0.0.1/private')
