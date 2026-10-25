"""Conservative credential redaction shared by tools, traces, and reports."""

import re
import json


_TOKEN_PATTERNS = (
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"\bAQ\.[A-Za-z0-9_.-]{20,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}\b"),
    re.compile(r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@"),
)
_KNOWN_SECRETS: set[str] = set()
_SECRET_NAME = r"[\w.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|credential)[\w.-]*"
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----[\s\S]*?"
    r"(?:-----END (?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----|\Z)"
)
_KEY_BOUNDARY = re.compile(r"-----\s*(?:BEGIN|END) (?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----")
_YAML_HEADER = re.compile(r"^(?P<indent>[ \t]*)[\"']?" + _SECRET_NAME + r"[\"']?\s*:\s*[|>][+\-0-9]*\s*(?:#.*)?$", re.I)
_TRIPLE_QUOTED = re.compile(
    r"(?P<prefix>\b" + _SECRET_NAME + r"\b\s*=\s*)(?P<quote>\"\"\"|''')(?P<body>[\s\S]*?)(?P=quote)", re.I
)
_HCL_SECRET = re.compile(r'\bvariable[ \t]+"' + _SECRET_NAME + r'"[ \t\r\n]*\{', re.I)
_HCL_DEFAULT = re.compile(r'''(?m)(\bdefault[ \t]*=[ \t]*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\r\n]+)''')
_ASSIGNMENT = re.compile(
    r"(?im)(\b" + _SECRET_NAME + r"\b[\"']?[ \t]*[:=][ \t]*)"
    r'''("(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^\r\n,;]+)'''
)
_PLACEHOLDER = re.compile(
    r"^(?:\s*|[\"']?\s*(?:\$\{.*\}|\$\w+|\{\{.*\}\}|os\.(?:getenv|environ).*|"
    r"process\.env\..*|None|null|true|false|your[_ -].*|example.*|placeholder.*|changeme|"
    r"<[^>]*>|\*+|\[REDACTED[^\]]*\])\s*[\"']?\s*)$", re.I
)


def protect_secret(value: str) -> None:
    if value and len(value) >= 4:
        _KNOWN_SECRETS.add(value)


def _remember_multiline(value: str) -> None:
    protect_secret(value.strip())
    for line in value.splitlines():
        protect_secret(line.strip())


def _block_end(text, start):
    """Locate a HCL block end while ignoring quoted braces and comments."""
    depth, quoted, index = 1, False, start
    while index < len(text):
        character = text[index]
        if quoted:
            if character == '\\':
                index += 2
                continue
            if character == '"':
                quoted = False
        elif text.startswith('/*', index):
            closing = text.find('*/', index + 2)
            index = len(text) if closing < 0 else closing + 2
            continue
        elif character == '#' or text.startswith('//', index):
            closing = text.find('\n', index)
            index = len(text) if closing < 0 else closing + 1
            continue
        elif character == '"':
            quoted = True
        elif character == '{':
            depth += 1
        elif character == '}':
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return len(text)


def _named_defaults(text):
    output, previous = [], 0
    for match in _HCL_SECRET.finditer(text):
        if match.start() < previous:
            continue
        end = _block_end(text, match.end())
        body = text[match.end():end]

        def replace_default(value_match):
            literal = value_match.group(2).strip()
            if literal in {'""', "''"} or _PLACEHOLDER.fullmatch(literal):
                return value_match.group(0)
            if literal.startswith('"') and literal.endswith('"'):
                try:
                    _remember_multiline(json.loads(literal))
                except (ValueError, TypeError):
                    _remember_multiline(literal[1:-1])
            else:
                _remember_multiline(literal)
            return value_match.group(1) + '[REDACTED: credential default]' + '\n' * value_match.group(2).count('\n')

        output.append(text[previous:match.end()])
        output.append(_HCL_DEFAULT.sub(replace_default, body))
        previous = end
    output.append(text[previous:])
    return ''.join(output)


def _multiline(text: str) -> str:
    def private_key(match):
        output = []
        for line in match.group(0).splitlines(keepends=True):
            value = line.rstrip("\r\n")
            newline = line[len(value):]
            if _KEY_BOUNDARY.fullmatch(value):
                output.append(value + newline)
            else:
                _remember_multiline(value)
                output.append("[REDACTED: private key]" + newline)
        return "".join(output)

    text = _PRIVATE_KEY.sub(private_key, text)

    def triple_quoted(match):
        _remember_multiline(match["body"])
        return (match["prefix"] + match["quote"] + "[REDACTED: multiline credential]"
                + "\n" * match["body"].count("\n") + match["quote"])

    text = _TRIPLE_QUOTED.sub(triple_quoted, text)
    lines = text.splitlines(keepends=True)
    index = 0
    while index < len(lines):
        match = _YAML_HEADER.fullmatch(lines[index].rstrip("\r\n"))
        index += 1
        if not match:
            continue
        indentation = len(match["indent"])
        while index < len(lines):
            original = lines[index]
            value = original.rstrip("\r\n")
            if value.strip() and len(value) - len(value.lstrip(" \t")) <= indentation:
                break
            if value.strip() and not _PLACEHOLDER.fullmatch(value.strip()):
                _remember_multiline(value)
                prefix = value[:len(value) - len(value.lstrip(" \t"))]
                lines[index] = prefix + "[REDACTED: multiline credential]" + original[len(value):]
            index += 1
    return "".join(lines)


def redact(text: str) -> str:
    """Remove token-like strings; keep line counts stable for evidence locations."""
    def replace_token(match):
        protect_secret(match.group(0))
        return "[REDACTED]" + "\n" * match.group(0).count("\n")

    text = _multiline(_named_defaults(text))
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub(replace_token, text)

    def replace_assignment(match):
        value = match.group(2).strip()
        if value in {"''", '""'} or _PLACEHOLDER.fullmatch(value):
            return match.group(0)
        if re.fullmatch(r"[|>][+\-0-9]*\s*(?:#.*)?", value):
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
            for child in item.values():
                visit(child)

    def render(item):
        if isinstance(item, str):
            return redact(item)
        if isinstance(item, list):
            return [render(child) for child in item]
        if isinstance(item, dict):
            # Keys belong to our tool/report protocol, not repository content.
            # Severity enum values are also structural, prevalidated metadata.
            return {key: child if key == "severity" and isinstance(child, str)
                    and child in {"critical", "high", "medium", "low"} else render(child)
                    for key, child in item.items()}
        return item

    visit(value)
    return render(value)
