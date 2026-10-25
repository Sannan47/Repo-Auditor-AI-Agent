"""Validate the assignment's exact JSON contract and observed locations."""

from auditor.repository import AuditError
from auditor.safety import sanitize


FIELDS = {"rule_id", "category", "severity", "file", "line", "description", "evidence", "recommendation"}
VIOLATION_SCHEMA = {
    "type": "object",
    "properties": {
        **{name: {"type": "string", "minLength": 1} for name in (
            "rule_id", "category", "description", "evidence", "recommendation")},
        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
        "file": {"type": ["string", "null"]},
        "line": {"type": ["integer", "null"], "minimum": 1},
    },
    "required": sorted(FIELDS), "additionalProperties": False,
}
REPORT_SCHEMA = {
    "type": "object",
    "properties": {"repository": {"type": "string", "description": "The exact full https://github.com/OWNER/REPOSITORY URL supplied for this audit"}, "violations": {"type": "array", "items": VIOLATION_SCHEMA}},
    "required": ["repository", "violations"], "additionalProperties": False,
}


def _validate_report(report: dict, repository: str, tools) -> dict:
    if not isinstance(report, dict) or set(report) != {"repository", "violations"}:
        raise AuditError("Report must contain exactly repository and violations")
    if report["repository"] != repository:
        raise AuditError(f"Report repository must equal {repository!r}; use the full inspected GitHub URL, not owner/repo")
    if not isinstance(report["violations"], list):
        raise AuditError("violations must be an array")
    findings, seen = [], set()
    for finding in report["violations"]:
        if not isinstance(finding, dict) or set(finding) != FIELDS:
            raise AuditError("Each violation must contain all nine required fields and no extra fields")
        for field in FIELDS - {"file", "line"}:
            if not isinstance(finding[field], str) or not finding[field].strip():
                raise AuditError(f"Violation {field} must be a nonempty string")
        if finding["severity"] not in {"critical", "high", "medium", "low"}:
            raise AuditError("Invalid violation severity")
        path, line = finding["file"], finding["line"]
        if path is not None:
            if not isinstance(path, str) or path not in tools.observed:
                raise AuditError("Finding file must have been inspected with read_file or search_code")
            if line is not None and (type(line) is not int or line not in tools.observed[path]):
                raise AuditError("Finding line must be a positive integer observed by an inspection tool")
        elif line is not None:
            raise AuditError("A finding without a file must have line=null")
        elif not tools.listing_complete:
            raise AuditError("Repository-level findings require a complete file listing")
        key = (finding["rule_id"].casefold(), path, line)
        semantic_key = (finding["description"].strip().casefold(), path, line)
        if key not in seen and semantic_key not in seen:
            findings.append(finding)
            seen.update((key, semantic_key))
    return {"repository": repository, "violations": findings}


def validate_report(report: dict, repository: str, tools) -> dict:
    report = _validate_report(report, repository, tools)
    sanitized = sanitize(report)
    # Redaction is not allowed to bypass structural or location validation.
    return _validate_report(sanitized, repository, tools)
