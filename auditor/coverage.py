"""Evidence-linked coverage bookkeeping, not a scanner or a tool-selection policy."""

from pathlib import PurePosixPath

from auditor.repository import AuditError


AREAS = (
    'repository_hygiene', 'dependency_management', 'code_quality', 'testing', 'ci',
    'security', 'configuration', 'collaboration', 'build_release',
)
_MANIFESTS = {
    'requirements.txt', 'pyproject.toml', 'setup.py', 'setup.cfg', 'pipfile',
    'package.json', 'cargo.toml', 'go.mod', 'gemfile', 'pom.xml', 'build.gradle',
    'build.gradle.kts', 'composer.json', 'packages.config', 'environment.yml',
    'environment.yaml', 'mix.exs', 'pubspec.yaml', 'deno.json', 'deno.jsonc',
}
_SOURCE_SUFFIXES = {'.py', '.js', '.ts', '.tsx', '.jsx', '.go', '.rs', '.java', '.cs', '.rb', '.php', '.sh', '.tf', '.hcl', '.c', '.cpp', '.kt', '.swift'}


def anchors(area, paths):
    """Identify relevant evidence types; do not infer defects from file names."""
    selected = []
    for path in paths:
        pure = PurePosixPath(path)
        name = pure.name.lower()
        workflow = path.startswith('.github/workflows/') and pure.suffix in {'.yml', '.yaml'}
        manifest = name in _MANIFESTS or name.startswith('requirements') and pure.suffix == '.txt' or pure.suffix in {'.csproj', '.fsproj'}
        source = pure.suffix.lower() in _SOURCE_SUFFIXES and not path.startswith(('tests/', 'test/'))
        infrastructure = pure.suffix.lower() in {'.tf', '.tfvars', '.hcl'} or name.startswith(('dockerfile', 'docker-compose', 'compose.'))
        relevant = {
            'repository_hygiene': name.startswith('readme'),
            'dependency_management': manifest,
            'code_quality': source or name in {'.ruff.toml', 'ruff.toml', '.eslintrc.json', '.prettierrc'},
            'testing': workflow or path.startswith(('tests/', 'test/')),
            'ci': workflow or name in {'.gitlab-ci.yml', 'jenkinsfile', '.travis.yml', 'azure-pipelines.yml'},
            'security': source or workflow or infrastructure or name in {'.env', '.env.example'},
            'configuration': infrastructure or name in {'.env', '.env.example'} or 'config' in name or workflow,
            'collaboration': workflow or name in {'contributing.md', 'codeowners', 'pull_request_template.md'},
            'build_release': workflow or manifest or name in {'makefile', 'dockerfile', 'justfile'},
        }[area]
        if relevant:
            selected.append(path)
    return selected


class Coverage:
    def __init__(self):
        self.calls = {}
        self.paths = None
        self.assessments = {}

    def observe(self, call_id, name, arguments, result, turn):
        self.calls[call_id] = dict(name=name, arguments=dict(arguments), result=result, turn=turn)
        if name == 'list_files' and 'error' not in result:
            self.paths = result['files']

    def requirements(self):
        return {area: anchors(area, self.paths or []) for area in AREAS if area not in self.assessments}

    def record(self, assessments, turn):
        if self.paths is None:
            raise AuditError('Discover repository structure with list_files before recording coverage')
        if not isinstance(assessments, list) or not 1 <= len(assessments) <= len(AREAS):
            raise AuditError('Provide one to nine evidence-linked area assessments')
        proposed = {}
        for item in assessments:
            if not isinstance(item, dict) or set(item) != {'area', 'status', 'summary', 'evidence_calls'}:
                raise AuditError('Each assessment needs area, status, summary, and evidence_calls')
            area, status = item['area'], item['status']
            if area not in AREAS or area in proposed:
                raise AuditError('Assessment areas must be valid and unique')
            if status not in {'checked', 'not_applicable', 'unavailable'}:
                raise AuditError('Assessment status must be checked, not_applicable, or unavailable')
            if not isinstance(item['summary'], str) or not item['summary'].strip():
                raise AuditError('Explain the area conclusion and acceptable alternatives in summary')
            refs = item['evidence_calls']
            if not isinstance(refs, list) or not refs or any(not isinstance(ref, str) or ref not in self.calls for ref in refs):
                raise AuditError('Coverage must cite actual inspection_id values from tool results. Available IDs: ' + ', '.join(self.calls))
            calls = [self.calls[ref] for ref in refs]
            if any(call['turn'] >= turn for call in calls):
                raise AuditError('Interpret inspection outputs in a later turn before recording coverage')
            expected = anchors(area, self.paths)
            reads = {call['arguments'].get('path') for call in calls
                     if call['name'] == 'read_file' and 'error' not in call['result']
                     and (call['result'].get('lines') or call['result'].get('total_lines') == 0)}
            if status == 'unavailable':
                if not any('error' in call['result'] or call['result'].get('truncated') for call in calls):
                    raise AuditError('Unavailable coverage must cite an actual failed or truncated check')
                if expected and not any(call['arguments'].get('path') in expected
                                        or call['name'] == 'list_files' and call['result'].get('truncated') for call in calls):
                    raise AuditError(f'{area}: cite the unavailable relevant artifact, not an unrelated failure')
            elif status == 'not_applicable' and expected:
                raise AuditError(f'{area}: relevant artifacts exist; inspect them and record checked or an actual limitation')
            elif expected and not reads.intersection(expected):
                raise AuditError(f'{area}: read relevant artifact content before assessing this area: {expected[:8]}')
            elif area in {'dependency_management', 'ci'} and set(expected) - reads:
                raise AuditError(f'{area}: inspect the remaining manifests/workflows before concluding: {sorted(set(expected) - reads)[:8]}')
            elif self.paths and not reads:
                raise AuditError(f'{area}: a listing or empty search alone is insufficient; inspect contextual content')
            proposed[area] = item
        self.assessments.update(proposed)
        return {'recorded': list(proposed), 'pending': list(self.requirements())}

    def assert_ready(self):
        pending = self.requirements()
        if self.paths is None or pending:
            raise AuditError('Coverage incomplete: record evidence-linked assessments for ' + ', '.join(pending))
        if self.paths and not any(call['name'] == 'read_file' and 'error' not in call['result']
                                  and (call['result'].get('lines') or call['result'].get('total_lines') == 0)
                                  for call in self.calls.values()):
            raise AuditError('Cannot complete an audit without inspecting repository content')
