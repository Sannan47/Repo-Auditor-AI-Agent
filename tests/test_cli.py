import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import agent
from auditor.provider import Settings
from auditor.repository import AuditError, git_command


class CLITests(unittest.TestCase):
    def test_invalid_url_fails_without_network(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = agent.main(["--repo", "file:///tmp/repo", "--output", "unused.json"])
        self.assertEqual(code, 1)
        self.assertIn("public repository URL", stderr.getvalue())

    def test_missing_configuration(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(AuditError):
            Settings.from_environment()

    def test_invalid_limits(self):
        for limit in ("0", "101", "bad"):
            with patch.dict(os.environ, {"LLM_API_KEY": "dummy", "LLM_MODEL": "dummy", "AGENT_MAX_ROUNDS": limit}), self.assertRaises(AuditError):
                Settings.from_environment()

    def test_git_timeout_and_missing_executable(self):
        for error in (subprocess.TimeoutExpired("git", 1), FileNotFoundError()):
            with patch("auditor.repository.subprocess.run", side_effect=error), self.assertRaises(AuditError):
                git_command(["status"])

    def test_report_write_is_atomic_on_serialization_failure(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "report.json"
            path.write_text('previous report', encoding="utf-8")
            with self.assertRaises(TypeError):
                agent.write_report(path, {"invalid": object()})
            self.assertEqual(path.read_text(), "previous report")
            self.assertEqual(list(Path(work).iterdir()), [path])

    def test_report_write_valid_json(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "report.json"
            report = {"repository": "https://github.com/example/demo", "violations": []}
            agent.write_report(path, report)
            self.assertEqual(json.loads(path.read_text()), report)


if __name__ == "__main__":
    unittest.main()
