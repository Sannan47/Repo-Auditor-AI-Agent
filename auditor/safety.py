"""Conservative credential redaction shared by tools, traces, and reports."""

import re


_TOKEN_PATTERNS = (
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\Z)"),
    re.compile(r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@"),
)
_ASSIGNMENT = re.compile(
    r"(?im)(\b[\w.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|credential)[\w.-]*\b"
    r"[\"']?\s*[:=]\s*)([^\r\n,;]+)"
)
_PLACEHOLDER = re.compile(
    r"^(?:\s*|[\"']?\s*(?:\$\{.*\}|\$\w+|\{\{.*\}\}|os\.(?:getenv|environ).*|"
    r"process\.env\..*|None|null|true|false|your[_ -].*|example.*|placeholder.*|changeme|"
    r"<[^>]*>|\*+|\[REDACTED[^\]]*\])\s*[\"']?\s*)$", re.I
)


def redact(text: str) -> str:
    """Remove token-like strings; keep line counts stable for evidence locations."""
    def replace_token(match):
        return "[REDACTED]" + "\n" * match.group(0).count("\n")

    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub(replace_token, text)

    def replace_assignment(match):
        value = match.group(2).strip()
        if _PLACEHOLDER.fullmatch(value):
            return match.group(0)
        return match.group(1) + "[REDACTED: possible credential]"

    return _ASSIGNMENT.sub(replace_assignment, text)


def sanitize(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, dict):
        return {redact(str(key)): sanitize(item) for key, item in value.items()}
    return value
