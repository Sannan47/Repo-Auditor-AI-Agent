import json
import tempfile
import unittest
from pathlib import Path

from auditor.engine import Trace, run_agent
from auditor.report import validate_report
from auditor.repository import AuditError
from test_tools import RepositoryFixture


URL = "https://github.com/example/demo"


def call(name, **arguments):
    return {"role": "assistant", "content": None, "tool_calls": [
        {"id": "call_" + name, "type": "function", "function": {
            "name": name, "arguments": json.dumps({"reason": "Inspect the available evidence", **arguments})}}]}


def finding(**overrides):
    return {"rule_id": "SEC-001", "category": "security", "severity": "high", "file": "config.py", "line": 1,
            "description": "Hardcoded password", "evidence": "Password assigned directly on line 1",
            "recommendation": "Read the password from the environment", **overrides}


class ScriptedProvider:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.inputs = []

    def complete(self, messages, definitions):
        self.inputs.append(list(messages))
        return next(self.responses)


class AgentTests(RepositoryFixture, unittest.TestCase):
    def run_script(self, responses, rounds=10):
        provider = ScriptedProvider(responses)
        with Trace(self.root / "audit.trace.jsonl") as trace:
            report = run_agent(URL, self.tools, provider, trace, max_rounds=rounds)
        return report, provider

    def test_dynamic_follow_up_and_authentic_evidence(self):
        report, provider = self.run_script([
            call("list_files"), call("search_code", pattern="password"),
            call("read_file", path="config.py"),
            call("submit_report", report={"repository": URL, "violations": [finding()]}),
        ])
        self.assertEqual(len(report["violations"]), 1)
        tool_messages = [m for m in provider.inputs[2] if m["role"] == "tool"]
        self.assertIn("config.py", tool_messages[-1]["content"])
        trace = (self.root / "audit.trace.jsonl").read_text()
        self.assertNotIn("a-private-value", trace)
        self.assertIn('"event": "completed"', trace)

    def test_empty_report_is_valid_after_inspection(self):
        report, _ = self.run_script([call("list_files"), call("read_file", path="README.md"),
            call("submit_report", report={"repository": URL, "violations": []})])
        self.assertEqual(report["violations"], [])

    def test_bad_report_is_returned_for_correction(self):
        report, provider = self.run_script([
            call("list_files"), call("read_file", path="config.py"),
            call("submit_report", report={"repository": URL, "violations": [finding(line=999)]}),
            call("submit_report", report={"repository": URL, "violations": [finding()]}),
        ])
        self.assertEqual(report["violations"][0]["line"], 1)
        self.assertIn("observed", str(provider.inputs[-1]))

    def test_no_inspection_cannot_claim_clean(self):
        with self.assertRaises(AuditError):
            self.run_script([call("submit_report", report={"repository": URL, "violations": []})], rounds=1)

    def test_tool_error_is_available_for_follow_up(self):
        _, provider = self.run_script([call("read_file", path="missing"), call("list_files"),
            call("submit_report", report={"repository": URL, "violations": []})])
        self.assertIn("does not exist", str(provider.inputs[1]))

    def test_report_contract_and_duplicates(self):
        self.tools.execute("read_file", {"path": "config.py"})
        report = {"repository": URL, "violations": [finding(), finding()]}
        self.assertEqual(len(validate_report(report, URL, self.tools)["violations"]), 1)
        for bad in (finding(severity="urgent"), finding(file="unseen.py"), finding(line=True), finding(extra="x")):
            with self.subTest(bad=bad), self.assertRaises(AuditError):
                validate_report({"repository": URL, "violations": [bad]}, URL, self.tools)


if __name__ == "__main__":
    unittest.main()
