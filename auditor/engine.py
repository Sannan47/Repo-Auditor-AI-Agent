"""Our explicit observe/reason/select/execute/interpret/report control loop."""

import json
from pathlib import Path

from auditor.coverage import AREAS, Coverage
from auditor.prompts import REVIEW_PROMPT, SYSTEM_PROMPT
from auditor.report import REPORT_SCHEMA, validate_report
from auditor.repository import AuditError
from auditor.safety import sanitize


def function(name, description, properties=None, required=()):
    properties = dict(properties or {})
    properties["reason"] = {"type": "string", "description": "Brief observation and purpose motivating this call"}
    return {"type": "function", "function": {"name": name, "description": description,
        "parameters": {"type": "object", "properties": properties,
                       "required": [*required, "reason"], "additionalProperties": False}}}


TOOL_DEFINITIONS = [
    function("list_files", "List tracked repository files; reports whether listing is complete."),
    function("read_file", "Read numbered text lines. Follow next_line to inspect more content.", {
        "path": {"type": "string"}, "start_line": {"type": "integer", "minimum": 1},
        "end_line": {"type": "integer", "minimum": 1}}, ("path",)),
    function("search_code", "Search tracked text files using a case-insensitive LITERAL substring (not regex).", {
        "pattern": {"type": "string"}}, ("pattern",)),
    function("git_log", "Inspect latest 30 commit subjects from a shallow clone of up to 100 commits."),
    function('read_action_metadata', 'Read public GitHub Action metadata at its actual ref. Use to verify version-specific protections such as checkout allow-unsafe-pr-checkout. Anonymous source read only; never executes the action.', {
        'action': {'type': 'string', 'description': 'owner/repository[/action-path]@ref, preferably the exact workflow SHA'}}, ('action',)),
    function("record_assessments", "Record evidence-linked conclusions for the nine inspection areas; cite earlier inspection tool-call IDs. This tool never detects violations.", {
        "assessments": {"type": "array", "minItems": 1, "maxItems": 9, "items": {
            "type": "object", "properties": {
                "area": {"type": "string", "enum": list(AREAS)},
                "status": {"type": "string", "enum": ["checked", "not_applicable", "unavailable"]},
                "summary": {"type": "string"},
                "evidence_calls": {"type": "array", "items": {"type": "string"}, "minItems": 1}},
            "required": ["area", "status", "summary", "evidence_calls"], "additionalProperties": False}}}, ("assessments",)),
    function("submit_report", "Finish after interpreting prior results; report exact evidence-backed findings.", {
        "report": REPORT_SCHEMA}, ("report",)),
]


class Trace:
    def __init__(self, path: Path):
        self.path = path
        self.stream = None

    def __enter__(self):
        self.stream = self.path.open("w", encoding="utf-8")
        return self

    def write(self, event: str, **data):
        self.stream.write(json.dumps(sanitize({"event": event, **data}), ensure_ascii=True) + "\n")
        self.stream.flush()

    def __exit__(self, *args):
        self.stream.close()


def run_agent(repository, tools, provider, trace, max_rounds=30):
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Audit {repository}. You have at most {max_rounds} model turns. Investigate now."},
    ]
    successful_inspections = 0
    reviewing = False
    coverage = Coverage()
    for turn in range(1, max_rounds + 1):
        independent_review = None
        try:
            message = provider.complete(messages, TOOL_DEFINITIONS)
        finally:
            if hasattr(provider, 'drain_retry_events'):
                for event in provider.drain_retry_events():
                    trace.write('provider_retry', turn=turn, **event)
        if not isinstance(message, dict) or message.get("role") != "assistant":
            raise AuditError("LLM returned an invalid assistant message")
        calls = message.get("tool_calls") or []
        if not isinstance(calls, list) or len(calls) > 8:
            raise AuditError("LLM returned an invalid or excessive batch of tool calls")
        trace.write("decision", turn=turn, message=message)
        messages.append(message)
        if not calls:
            messages.append({"role": "user", "content": "Continue investigating with tools or finish using submit_report. Plain text is not a completed inspection."})
            continue
        for call in calls:
            try:
                name = call["function"]["name"]
                call_id = call["id"]
                arguments = json.loads(call["function"]["arguments"])
                if not isinstance(arguments, dict):
                    raise ValueError("Tool arguments must be a JSON object")
                reason = arguments.pop("reason", "")
                if not isinstance(reason, str) or not reason.strip():
                    raise ValueError("Each tool call must explain its purpose in reason")
                if name == "submit_report":
                    if len(calls) != 1:
                        raise AuditError("submit_report must be the only call in its turn; interpret inspection outputs first")
                    if not successful_inspections:
                        raise AuditError("An actual inspection is required before submitting a report")
                    if set(arguments) != {"report"}:
                        raise AuditError("submit_report expects exactly report and reason")
                    coverage.assert_ready()
                    report = validate_report(arguments["report"], repository, tools)
                    if reviewing:
                        trace.write("completed", turn=turn, reason=reason, report=report)
                        return report
                    reviewing = True
                    trace.write("candidate_report", turn=turn, report=report)
                    result = {"status": "review_required", "candidate_report": report,
                              "coverage": coverage.assessments, "instructions": REVIEW_PROMPT}
                    independent_review = {
                        'status': 'review_required', 'repository': repository,
                        'instructions': REVIEW_PROMPT + '\nIndependently inspect the supplied primary observations. The candidate can contain false positives or omit real issues. Do not defer to the first pass or treat educational intent as a waiver for runnable unsafe configuration.',
                        'candidate_report': report,
                        'coverage_evidence': {area: {'status': item['status'], 'evidence_calls': item['evidence_calls']}
                                              for area, item in coverage.assessments.items()},
                        'source_observations': [{'inspection_id': key, 'tool': entry['name'],
                                                 'arguments': entry['arguments'], 'result': entry['result']}
                                                for key, entry in coverage.calls.items()],
                    }
                elif name == 'record_assessments':
                    if set(arguments) != {'assessments'}:
                        raise AuditError('record_assessments expects assessments and reason')
                    result = coverage.record(arguments['assessments'], turn)
                    trace.write('coverage', turn=turn, assessments=coverage.assessments)
                else:
                    result = tools.execute(name, arguments)
                    coverage.observe(call_id, name, arguments, result, turn)
                    # Some providers do not expose transport call IDs to the model.
                    # Put the evidence ID in visible result content explicitly.
                    result = {**result, 'inspection_id': call_id}
                    if "error" not in result:
                        successful_inspections += 1
            except (KeyError, TypeError) as exc:
                raise AuditError("LLM returned a malformed tool call") from exc
            except (ValueError, AuditError) as exc:
                result = {"error": str(exc)}
                name = call.get("function", {}).get("name", "invalid")
                call_id = call.get("id")
                if not call_id:
                    raise AuditError("LLM tool call has no ID") from exc
            result = sanitize(result)
            trace.write("tool_result", turn=turn, name=name, call_id=call_id, result=result)
            if independent_review is not None:
                # Start a fresh reviewer context from primary evidence, not a
                # long chain of the first pass's possibly mistaken conclusions.
                # The same tools, clone, observation ledger and turn cap remain.
                messages = [{'role': 'system', 'content': SYSTEM_PROMPT},
                            {'role': 'user', 'content': json.dumps(sanitize(independent_review))}]
                trace.write('review_context', turn=turn, mode='independent_primary_evidence',
                            inspection_count=len(coverage.calls))
            else:
                messages.append({"role": "tool", "tool_call_id": call_id, "content": json.dumps(result)})
        messages.append({"role": "user", "content": f"Interpret the tool results and select your next action. {max_rounds - turn} model turns remain. Investigation ledger: {json.dumps(coverage.planning_context())}. Choose investigations dynamically. Batch independent unread file inspections (at most eight calls per turn), then record only areas with actual evidence. Valid assessments persist if other areas need correction; never send empty evidence_calls."})
    raise AuditError("Agent exhausted its model-turn budget without a validated report; inspect the trace or increase AGENT_MAX_ROUNDS")
