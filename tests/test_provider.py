import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from auditor.provider import OpenAICompatibleProvider
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


if __name__ == "__main__":
    unittest.main()
