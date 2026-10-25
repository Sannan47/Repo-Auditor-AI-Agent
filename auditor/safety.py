"""Conservative credential redaction shared by tools, traces, and reports."""

import re


_TOKEN_PATTERNS = (
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"\bAQ\.[A-Za-z0-9_.-]{20,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\Z)"),
    re.compile(r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@"),
)
_KNOWN_SECRETS: set[str] = set()
_ASSIGNMENT = re.compile(
    r"(?im)(\b[\w.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|credential)[\w.-]*\b"
    r"[\"']?\s*[:=]\s*)([^\r\n,;]+)"
)
_PLACEHOLDER = re.compile(
    r"^(?:\s*|[\"']?\s*(?:\$\{.*\}|\$\w+|\{\{.*\}\}|os\.(?:getenv|environ).*|"
    r"process\.env\..*|None|null|true|false|your[_ -].*|example.*|placeholder.*|changeme|"
    r"<[^>]*>|\*+|\[REDACTED[^\]]*\])\s*[\"']?\s*)$", re.I
)


def protect_secret(value: str) -> None:
    if value and len(value) >= 4:
        _KNOWN_SECRETS.add(value)


def redact(text: str) -> str:
    """Remove token-like strings; keep line counts stable for evidence locations."""
    def replace_token(match):
        protect_secret(match.group(0))
        return "[REDACTED]" + "\n" * match.group(0).count("\n")

    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub(replace_token, text)

    def replace_assignment(match):
        value = match.group(2).strip()
        if _PLACEHOLDER.fullmatch(value):
            return match.group(0)
        # Remember literal values so an echoed value without its variable label
        # is also removed from later tool output and model-generated findings.
        literal = re.fullmatch(r'''["']([^"']+)["']\s*(?:\#.*)?''', value)
        if literal:
            protect_secret(literal.group(1))
        elif re.fullmatch(r"[A-Za-z0-9_./+=@!$%-]{4,}", value):
            protect_secret(value)
        return match.group(1) + "[REDACTED: possible credential]"

    text = _ASSIGNMENT.sub(replace_assignment, text)
    for secret in sorted(_KNOWN_SECRETS, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]" + "\n" * secret.count("\n"))
    return text


def sanitize(value):
    # Discover credentials throughout a response before rendering it: an earlier
    # line may echo a password whose assignment appears later in the same file.
    def visit(item):
        if isinstance(item, str):
            redact(item)
        elif isinstance(item, list):
            for child in item:
                visit(child)
        elif isinstance(item, dict):
            for key, child in item.items():
                redact(str(key))
                visit(child)

    def render(item):
        if isinstance(item, str):
            return redact(item)
        if isinstance(item, list):
            return [render(child) for child in item]
        if isinstance(item, dict):
            return {redact(str(key)): render(child) for key, child in item.items()}
        return item

    visit(value)
    return render(value)
