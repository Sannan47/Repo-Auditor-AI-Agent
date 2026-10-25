import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from auditor.engine import Trace
from auditor.report import FIELDS, validate_report
from auditor.repository import AuditError
from auditor.safety import _KNOWN_SECRETS, redact, sanitize
from test_tools import RepositoryFixture
from tools import MAX_OUTPUT_CHARS


class SafetyTests(RepositoryFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.previous = _KNOWN_SECRETS.copy()
        _KNOWN_SECRETS.clear()

    def tearDown(self):
        _KNOWN_SECRETS.clear()
        _KNOWN_SECRETS.update(self.previous)
        super().tearDown()

    def test_private_key_read_search_and_trace_never_expose_body(self):
        body = 'U1lOVEhFVElDX09OTFlfTk9UX0FfUkVBTF9LRVk='
        content = '-----BEGIN PRIVATE KEY-----\n' + body + '\n-----END PRIVATE KEY-----\nafter = 1\n'
        (self.root / 'private.pem').write_text(content)
        import subprocess
        subprocess.run(['git', '-C', str(self.root), 'add', 'private.pem'], check=True)
        # Read only the body, so redaction must see context outside the requested page.
        result = self.tools.execute('read_file', {'path': 'private.pem', 'start_line': 2, 'end_line': 2})
        self.assertNotIn(body, json.dumps(result))
        self.assertEqual(result['lines'][0]['line'], 2)
        self.assertIn('REDACTED', result['lines'][0]['text'])
        result = self.tools.execute('search_code', {'pattern': 'PRIVATE KEY'})
        with Trace(self.root / 'safe.jsonl') as trace:
            trace.write('tool_result', result=result, echo=body)
        self.assertNotIn(body, (self.root / 'safe.jsonl').read_text())
        self.assertEqual(len(redact(content).splitlines()), len(content.splitlines()))

    def test_yaml_literal_and_folded_passwords_keep_locations(self):
        for marker in ('|', '>-'):
            with self.subTest(marker=marker):
                content = f'db_password: {marker}\n  synthetic-first-part\n  synthetic-second-part\nport: 8080\n'
                (self.root / 'config.py').write_text(content)
                result = self.tools.execute('read_file', {'path': 'config.py'})
                self.assertNotIn('synthetic-first-part', json.dumps(result))
                self.assertNotIn('synthetic-second-part', json.dumps(result))
                self.assertEqual(result['lines'][-1], {'line': 4, 'text': 'port: 8080'})

    def test_triple_quotes_and_delimiters_in_password(self):
        value = 'password = """\nsynthetic-triple-body\n"""\nnext = 1\n'
        self.assertNotIn('synthetic-triple-body', redact(value))
        self.assertEqual(redact(value).count('\n'), value.count('\n'))
        self.assertNotIn('comma,semi;colon', redact('password = "comma,semi;colon"'))

    def test_empty_credential_templates_do_not_consume_following_config(self):
        content = 'LLM_API_KEY=\nLLM_MODEL=gemini-3.1-flash-lite\npassword:\nport: 8080\nsecret=""\ntoken=\'\'\n'
        self.assertEqual(redact(content), content)

    def test_secret_words_cannot_rename_protocol_fields_or_severity(self):
        for word in (*FIELDS, 'repository', 'violations', 'high', 'critical', 'medium'):
            redact(f'password="{word}"')
        self.assertEqual(set(sanitize({'line': 4, 'file': 'example.py'})), {'line', 'file'})
        self.assertEqual(sanitize({'severity': 'high'})['severity'], 'high')
        self.tools.execute('read_file', {'path': 'config.py'})
        finding = dict(rule_id='SEC-001', category='security', severity='high', file='config.py', line=1,
                       description='Credential committed', evidence='Assignment at first row', recommendation='Rotate credential')
        report = validate_report({'repository': 'https://github.com/example/demo', 'violations': [finding]},
                                 'https://github.com/example/demo', self.tools)
        self.assertEqual(set(report['violations'][0]), FIELDS)
        self.assertEqual(report['violations'][0]['severity'], 'high')

    def test_sanitized_report_is_validated_again(self):
        with patch('auditor.report.sanitize', return_value={'repository': 'wrong', 'violations': []}):
            with self.assertRaises(AuditError):
                validate_report({'repository': 'https://github.com/example/demo', 'violations': []},
                                'https://github.com/example/demo', SimpleNamespace())

    def test_git_history_is_redacted_before_output_truncation(self):
        token = 'ghp_' + 'x' * 36
        history = 'a' * (MAX_OUTPUT_CHARS - 11) + ' ' + token + ' rest of subject'
        with patch('tools.git_command', return_value=history):
            result = self.tools.execute('git_log', {})
        self.assertFalse('ghp_' in result['history'])
        self.assertLessEqual(len(result['history']), MAX_OUTPUT_CHARS)

    def test_terraform_password_default_is_redacted_before_pagination(self):
        value = 'synthetic-hcl-credential'
        content = 'variable "db_password" {\n  description = "Password with a quoted } brace"\n  default = "' + value + '"\n}\nvariable "region" {\n  default = "us-east-1"\n}\n'
        (self.root / 'config.py').write_text(content)
        result = self.tools.execute('read_file', {'path': 'config.py', 'start_line': 3, 'end_line': 3})
        self.assertNotIn(value, str(result))
        self.assertEqual(result['lines'][0]['line'], 3)
        self.assertIn('credential default', result['lines'][0]['text'])
        self.assertIn('default = "us-east-1"', redact(content))
        self.assertNotIn(value, redact('Echo: ' + value))
        self.assertEqual(len(redact(content).splitlines()), len(content.splitlines()))

    def test_terraform_empty_and_environment_defaults_are_not_credentials(self):
        content = 'variable "api_key" {\n  default = ""\n}\nvariable "secret" {\n  default = "${var.secret_from_environment}"\n}\n'
        self.assertEqual(redact(content), content)
