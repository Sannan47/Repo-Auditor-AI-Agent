"""Anonymous, bounded source inspection for public GitHub Action metadata."""

from pathlib import PurePosixPath
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from auditor.repository import AuditError, normalize_url
from auditor.safety import redact


class GitHubOnlyRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = urlsplit(newurl)
        if destination.scheme != 'https' or destination.hostname != 'raw.githubusercontent.com':
            raise AuditError('Action metadata redirect left the allowed GitHub source host')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(url):
    request = Request(url, headers={'User-Agent': 'DevOps-Repository-Auditor', 'Accept': 'text/plain'})
    with build_opener(GitHubOnlyRedirects()).open(request, timeout=20) as response:
        content = response.read(512_001)
    if len(content) > 512_000 or b'\0' in content:
        raise AuditError('Action metadata is binary or exceeds the inspection limit')
    return content.decode('utf-8', errors='replace')


def read_action_metadata(action):
    if not isinstance(action, str) or action.count('@') != 1:
        raise AuditError('Use owner/repository[/action-path]@ref for a public GitHub Action')
    location, ref = action.split('@')
    parts = location.split('/')
    if len(parts) < 2 or any(part in {'', '.', '..'} for part in parts):
        raise AuditError('Invalid GitHub Action location')
    repository = normalize_url('https://github.com/' + '/'.join(parts[:2]))
    if not re.fullmatch(r'[A-Za-z0-9_./-]+', ref) or any(part in {'.', '..', ''} for part in ref.split('/')):
        raise AuditError('Invalid GitHub Action ref')
    if any(not re.fullmatch(r'[A-Za-z0-9_.-]+', part) for part in parts[2:]):
        raise AuditError('Invalid GitHub Action subdirectory')
    subdirectory = '/'.join(parts[2:])
    for filename in ('action.yml', 'action.yaml'):
        path = str(PurePosixPath(subdirectory) / filename)
        url = f'https://raw.githubusercontent.com/{"/".join(parts[:2])}/{quote(ref, safe="")}/{quote(path, safe="/")}'
        try:
            text = redact(_download(url))
            lines, chars = [], 0
            for number, line in enumerate(text.splitlines(), 1):
                chars += len(line)
                if chars > 32_000:
                    break
                lines.append({'line': number, 'text': line})
            return {'action': action, 'repository': repository, 'ref': ref, 'path': path,
                    'lines': lines, 'truncated': len(lines) < len(text.splitlines()),
                    'scope': 'External action metadata only; no target code or Actions workflow was executed.'}
        except HTTPError as exc:
            if exc.code == 404:
                continue
            raise AuditError(f'Public action metadata unavailable (HTTP {exc.code})') from None
        except (URLError, TimeoutError, OSError):
            raise AuditError('Public action metadata request failed or timed out') from None
    raise AuditError('No action.yml or action.yaml found at the specified public action ref')
