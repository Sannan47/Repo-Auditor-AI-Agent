import json
import tempfile
import unittest
from pathlib import Path

from auditor.engine import Trace, available_tools, run_agent
from auditor.coverage import AREAS, Coverage
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


def submissions(report):
    # Initial candidate followed by the provider's final reviewed report.
    return [call("submit_report", report=report), call("submit_report", report=report)]


def assessed():
    return call('record_assessments', assessments=[{
        'area': area, 'status': 'checked',
        'summary': 'Reviewed fixture content and applicable alternatives for ' + area,
        'evidence_calls': ['call_read_file', 'context'],
    } for area in AREAS])


def inspections():
    context = call('read_file', path='README.md')
    context['tool_calls'][0]['id'] = 'context'
    return [call('list_files'), context, call('read_file', path='config.py'), assessed()]


class ScriptedProvider:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.inputs = []
        self.definitions = []

    def complete(self, messages, definitions):
        self.inputs.append(list(messages))
        self.definitions.append(definitions)
        return next(self.responses)


class AgentTests(RepositoryFixture, unittest.TestCase):
    def run_script(self, responses, rounds=15):
        provider = ScriptedProvider(responses)
        with Trace(self.root / "audit.trace.jsonl") as trace:
            report = run_agent(URL, self.tools, provider, trace, max_rounds=rounds)
        return report, provider

    def test_dynamic_follow_up_and_authentic_evidence(self):
        report, provider = self.run_script([
            *inspections(), call("search_code", pattern="password"),
            *submissions({"repository": URL, "violations": [finding()]}),
        ])
        self.assertEqual(len(report["violations"]), 1)
        tool_messages = [m for m in provider.inputs[3] if m["role"] == "tool"]
        self.assertIn("config.py", tool_messages[-1]["content"])
        self.assertEqual(json.loads(tool_messages[-1]['content'])['inspection_id'], 'call_read_file')
        trace = (self.root / "audit.trace.jsonl").read_text()
        self.assertNotIn("a-private-value", trace)
        self.assertIn('"event": "completed"', trace)

    def test_empty_report_is_valid_after_inspection(self):
        report, _ = self.run_script([*inspections(),
            *submissions({"repository": URL, "violations": []})])
        self.assertEqual(report["violations"], [])

    def test_bad_report_is_returned_for_correction(self):
        report, provider = self.run_script([
            *inspections(),
            call("submit_report", report={"repository": URL, "violations": [finding(line=999)]}),
            *submissions({"repository": URL, "violations": [finding()]}),
        ])
        self.assertEqual(report["violations"][0]["line"], 1)
        self.assertTrue(any('observed' in str(messages) for messages in provider.inputs))

    def test_short_repository_name_returns_exact_url_for_recovery(self):
        report, provider = self.run_script([
            *inspections(),
            call('submit_report', report={'repository': 'example/demo', 'violations': []}),
            *submissions({'repository': URL, 'violations': []}),
        ])
        errors = [json.loads(message['content'])['error']
                  for messages in provider.inputs for message in messages
                  if message['role'] == 'tool' and 'error' in json.loads(message['content'])]
        self.assertTrue(any(URL in error and 'full inspected GitHub URL' in error for error in errors))
        self.assertEqual(report['repository'], URL)

    def test_double_encoded_report_is_decoded_then_fully_validated(self):
        report, provider = self.run_script([
            *inspections(),
            call('submit_report', report=json.dumps({'repository': URL, 'violations': [finding(line=999)]})),
            *submissions(json.dumps({'repository': URL, 'violations': [finding()]})),
        ])
        self.assertEqual(report['violations'][0]['line'], 1)
        self.assertTrue(any('observed' in str(messages) for messages in provider.inputs))

    def test_invalid_encoded_report_can_recover_without_schema_relaxation(self):
        report, provider = self.run_script([
            *inspections(),
            call('submit_report', report='{broken'),
            call('submit_report', report=json.dumps({'repository': URL, 'violations': [], 'extra': True})),
            *submissions({'repository': URL, 'violations': []}),
        ])
        self.assertEqual(report['violations'], [])
        self.assertTrue(any('report must be a JSON object' in str(messages) for messages in provider.inputs))
        self.assertTrue(any('exactly repository and violations' in str(messages) for messages in provider.inputs))

    def test_final_report_schema_pins_current_url_without_shared_mutation(self):
        _, provider = self.run_script([*inspections(), *submissions({'repository': URL, 'violations': []})])
        for definitions in provider.definitions[-2:]:
            submit = next(tool for tool in definitions if tool['function']['name'] == 'submit_report')
            prop = submit['function']['parameters']['properties']['report']['properties']['repository']
            self.assertEqual(prop['enum'], [URL])
        from auditor.report import REPORT_SCHEMA
        self.assertNotIn('enum', REPORT_SCHEMA['properties']['repository'])

    def test_no_inspection_cannot_claim_clean(self):
        with self.assertRaises(AuditError):
            self.run_script([call("submit_report", report={"repository": URL, "violations": []})], rounds=1)

    def test_tool_error_is_available_for_follow_up(self):
        _, provider = self.run_script([call("read_file", path="missing"), *inspections(),
            *submissions({"repository": URL, "violations": []})])
        self.assertIn("does not exist", str(provider.inputs[1]))

    def test_report_contract_and_duplicates(self):
        self.tools.execute("read_file", {"path": "config.py"})
        report = {"repository": URL, "violations": [finding(), finding()]}
        self.assertEqual(len(validate_report(report, URL, self.tools)["violations"]), 1)
        for bad in (finding(severity="urgent"), finding(file="unseen.py"), finding(line=True), finding(extra="x")):
            with self.subTest(bad=bad), self.assertRaises(AuditError):
                validate_report({"repository": URL, "violations": [bad]}, URL, self.tools)

    def test_review_can_reject_a_candidate(self):
        report, provider = self.run_script([*inspections(),
            call("submit_report", report={"repository": URL, "violations": [finding()]}),
            call("submit_report", report={"repository": URL, "violations": []})])
        self.assertEqual(report["violations"], [])
        self.assertIn("review_required", str(provider.inputs[-1]))

    def test_listing_only_cannot_complete_a_clean_report(self):
        with self.assertRaises(AuditError):
            self.run_script([call('list_files'), *submissions({'repository': URL, 'violations': []})], rounds=3)

    def test_unassessed_area_rejects_submission_and_allows_followup(self):
        report, provider = self.run_script([
            *inspections()[:3],
            call('submit_report', report={'repository': URL, 'violations': []}),
            assessed(), *submissions({'repository': URL, 'violations': []}),
        ])
        self.assertEqual(report['violations'], [])
        self.assertTrue(any('not available at the current evidence state' in str(messages) for messages in provider.inputs))

    def test_final_review_uses_primary_evidence_without_first_pass_anchoring(self):
        responses = inspections()
        responses[0]['content'] = 'First pass conclusion that should not bias the reviewer'
        responses += [call('submit_report', report={'repository': URL, 'violations': []}),
                      call('submit_report', report={'repository': URL, 'violations': [finding()]})]
        report, provider = self.run_script(responses)
        review = provider.inputs[-1]
        self.assertNotIn('First pass conclusion that should not bias the reviewer', str(review))
        self.assertIn('source_observations', str(review))
        self.assertIn('config.py', str(review))
        self.assertEqual(len(report['violations']), 1)

    def test_finalization_is_not_offered_before_evidence_is_ready(self):
        names = {tool['function']['name'] for tool in available_tools(Coverage())}
        self.assertIn('read_files', names)
        self.assertNotIn('submit_report', names)
        self.assertNotIn('record_assessments', names)

    def test_bulk_read_ids_support_real_coverage_and_reporting(self):
        record = call('record_assessments', assessments=[{
            'area': area, 'status': 'checked', 'summary': 'Reviewed fixture source',
            'evidence_calls': ['call_read_files_file_1', 'call_read_files_file_2']} for area in AREAS])
        report, provider = self.run_script([call('list_files'),
            call('read_files', paths=['README.md', 'config.py']), record,
            *submissions({'repository': URL, 'violations': [finding()]})])
        self.assertEqual(report['violations'][0]['line'], 1)
        self.assertIn('call_read_files_file_2', str(provider.inputs[2]))


if __name__ == "__main__":
    unittest.main()
