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
from test_agent import ScriptedProvider, call, submissions
from auditor.coverage import AREAS


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

    def test_full_cli_flow_and_trace_without_network(self):
        url = "https://github.com/example/demo"
        provider = ScriptedProvider([call("list_files"), call("read_file", path="README.md"),
            call('record_assessments', assessments=[{
                'area': area, 'status': 'checked', 'summary': 'Reviewed fixture context',
                'evidence_calls': ['call_read_file']} for area in AREAS]),
            *submissions({"repository": url, "violations": []})])

        def fake_clone(repository, destination):
            destination.mkdir()
            subprocess.run(["git", "init", "--quiet", str(destination)], check=True)
            (destination / "README.md").write_text("# Healthy fixture\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(destination), "add", "."], check=True)
            subprocess.run(["git", "-C", str(destination), "-c", "user.name=Fixture",
                            "-c", "user.email=fixture@example.invalid", "commit", "-qm", "Fixture"], check=True)

        with tempfile.TemporaryDirectory() as work:
            output = Path(work) / "report.json"
            with patch("agent.clone_repository", side_effect=fake_clone), \
                 patch("agent.OpenAICompatibleProvider", return_value=provider), \
                 patch("agent.Settings.from_environment", return_value=Settings("test-key", "test-model")), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(agent.main(["--repo", url, "--output", str(output)]), 0)
            self.assertEqual(json.loads(output.read_text()), {"repository": url, "violations": []})
            trace = [json.loads(line) for line in Path(str(output) + ".trace.jsonl").read_text().splitlines()]
            self.assertEqual(trace[1]["event"], "repository_snapshot")
            self.assertEqual(trace[-1]["event"], "completed")


if __name__ == "__main__":
    unittest.main()
