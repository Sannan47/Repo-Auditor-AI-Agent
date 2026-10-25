import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from auditor.provider import OpenAICompatibleProvider, _retry_delay
from auditor.repository import AuditError


class ProviderTests(unittest.TestCase):
    def provider(self, response=None, error=None):
        provider = OpenAICompatibleProvider.__new__(OpenAICompatibleProvider)
        provider.model = "test-model"
        provider.client = MagicMock()
        provider.client.chat.completions.create.return_value = response
        provider.client.chat.completions.create.side_effect = error
        return provider

    def test_provider_error_does_not_echo_credentials(self):
        error = RuntimeError("sensitive-request-content")
        provider = self.provider(error=error)
        with self.assertRaises(AuditError) as caught:
            provider.complete([], [])
        self.assertNotIn("sensitive-request-content", str(caught.exception))

    def test_incomplete_response_is_fatal(self):
        provider = self.provider(SimpleNamespace(choices=[SimpleNamespace(finish_reason="length")]))
        with self.assertRaises(AuditError):
            provider.complete([], [])

    def test_tool_metadata_is_preserved_for_provider_followup(self):
        call = MagicMock()
        payload = {"id": "c1", "type": "function", "function": {"name": "list_files", "arguments": "{}"},
                   "extra_content": {"google": {"thought_signature": "opaque-metadata"}}}
        call.model_dump.return_value = payload
        message = SimpleNamespace(content=None, tool_calls=[call])
        provider = self.provider(SimpleNamespace(choices=[SimpleNamespace(finish_reason="tool_calls", message=message)]))
        result = provider.complete([], [])
        self.assertEqual(result["tool_calls"][0], payload)

    def success(self):
        return SimpleNamespace(choices=[SimpleNamespace(finish_reason='stop', message=SimpleNamespace(content='OK', tool_calls=None))])

    def error(self, status=429, headers=None, body=None):
        error = RuntimeError('sensitive provider content')
        error.status_code = status
        error.response = SimpleNamespace(headers=headers or {})
        error.body = body
        return error

    def test_transient_throttle_retries_same_observations_and_honors_header(self):
        provider = self.provider()
        provider.max_retries, provider.retry_base = 2, 5
        provider.client.chat.completions.create.side_effect = [self.error(headers={'retry-after': '2'}), self.success()]
        messages = [{'role': 'user', 'content': 'Existing observations'}]
        with patch('auditor.provider.time.sleep') as sleep:
            result = provider.complete(messages, [])
        sleep.assert_called_once_with(2.0)
        self.assertEqual(result['content'], 'OK')
        self.assertEqual(provider.client.chat.completions.create.call_count, 2)
        self.assertTrue(all(call.kwargs['messages'] == messages for call in provider.client.chat.completions.create.call_args_list))
        self.assertEqual(len(provider.drain_retry_events()), 1)
        self.assertEqual(provider.drain_retry_events(), [])

    def test_backoff_is_bounded_and_exhaustion_is_useful(self):
        provider = self.provider(error=self.error(503))
        provider.max_retries, provider.retry_base = 2, 5
        with patch('auditor.provider.time.sleep') as sleep, patch('auditor.provider.random.uniform', return_value=0):
            with self.assertRaises(AuditError) as caught:
                provider.complete([], [])
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [5, 10])
        self.assertIn('3 attempt(s)', str(caught.exception))
        self.assertNotIn('sensitive provider content', str(caught.exception))

    def test_permanent_errors_and_daily_quota_are_not_retried(self):
        for error in (self.error(401), self.error(429, body={'details': [{'violations': [{'quotaId': 'RequestsPerDayPerProject'}]}]})):
            with self.subTest(status=error.status_code):
                provider = self.provider(error=error)
                provider.max_retries = 4
                with patch('auditor.provider.time.sleep') as sleep, self.assertRaises(AuditError):
                    provider.complete([], [])
                sleep.assert_not_called()
                self.assertEqual(provider.client.chat.completions.create.call_count, 1)

    def test_google_retry_info_and_oversized_delays(self):
        error = self.error(body={'error': {'details': [{'@type': 'type.googleapis.com/google.rpc.RetryInfo', 'retryDelay': '12.5s'}]}})
        self.assertEqual(_retry_delay(error, 0, 5), 12.5)
        with self.assertRaises(AuditError):
            _retry_delay(self.error(headers={'retry-after': '600'}), 0, 5)

    def test_google_list_envelope_daily_quota_fails_without_sleeping(self):
        error = self.error(body=[{'error': {'details': [
            {'violations': [{'quotaId': 'GenerateRequestsPerDayPerProjectPerModel-FreeTier', 'quotaValue': '20'}]},
            {'@type': 'type.googleapis.com/google.rpc.RetryInfo', 'retryDelay': '74014s'},
        ]}}])
        provider = self.provider(error=error)
        provider.max_retries = 4
        with patch('auditor.provider.time.sleep') as sleep, self.assertRaisesRegex(AuditError, 'daily or zero project quota'):
            provider.complete([], [])
        sleep.assert_not_called()
        self.assertEqual(provider.client.chat.completions.create.call_count, 1)

    def test_google_list_envelope_transient_retry_info_is_honored(self):
        error = self.error(body=[{'error': {'details': [
            {'@type': 'type.googleapis.com/google.rpc.RetryInfo', 'retryDelay': '3s'},
        ]}}])
        self.assertEqual(_retry_delay(error, 0, 5), 3)

    def test_malformed_quota_metadata_is_bounded(self):
        cyclic = []
        cyclic.append(cyclic)
        provider = self.provider(error=self.error(body=cyclic))
        with self.assertRaisesRegex(AuditError, 'HTTP 429'):
            provider.complete([], [])


if __name__ == "__main__":
    unittest.main()
