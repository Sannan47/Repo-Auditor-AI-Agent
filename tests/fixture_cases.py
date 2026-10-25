"""Synthetic repository content and evaluator labels; never supplied as agent answers."""

from copy import deepcopy


CI = '''name: Validate
on: [push, pull_request]
permissions:
  contents: read
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803
        with:
          persist-credentials: false
      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1
        with:
          python-version: '3.12'
      - run: python -m pip install . -r requirements-dev.txt
      - run: ruff check .
      - run: ruff format --check .
      - run: python -m unittest discover -s tests
      - run: python -m build
'''
BASE = {
    'README.md': '''# Arithmetic library
A small Python library with no runtime dependencies. Install with `pip install .`.
For development install `pip install . -r requirements-dev.txt`.
Run `python -m unittest discover -s tests`, `ruff check .`,
`ruff format --check .`, and `python -m build` before proposing changes.
This reusable library pins build/development tools, while consumers resolve their
own environments. No application lockfile or deployment service is required.
All CI checks must succeed. There is no automated deployment or auto-approval.
''',
    '.gitignore': '.venv/\n.env\n__pycache__/\nbuild/\ndist/\n*.egg-info/\n',
    '.env.example': 'APP_ENV=development\n',
    'CONTRIBUTING.md': 'Submit changes by PR with tests. Reviewers check behavior, security, and passing CI before approval.\n',
    'pyproject.toml': '''[build-system]
requires = ["setuptools==80.9.0"]
build-backend = "setuptools.build_meta"

[project]
name = "arithmetic-library"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = []

[tool.setuptools]
py-modules = ["app"]

[tool.ruff]
line-length = 88
''',
    'requirements-dev.txt': 'build==1.2.2.post1\nruff==0.11.13\n',
    'app.py': 'def add(a, b):\n    """Return the sum of two numbers."""\n    return a + b\n',
    'tests/test_app.py': '''import unittest

from app import add


class ArithmeticTests(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(1, 2), 3)
''',
    '.github/workflows/ci.yml': CI,
}

obvious = deepcopy(BASE)
obvious['pyproject.toml'] = BASE['pyproject.toml'].replace('dependencies = []', 'dependencies = ["requests==2.32.4"]')
obvious['requirements.txt'] = 'requests==2.31.0\n'
obvious['README.md'] += '\nDeployment installs both `pip install .` and `pip install -r requirements.txt` into the same environment.\n'
obvious['.github/workflows/ci.yml'] = CI.replace('python -m unittest discover -s tests', 'echo "Tests skipped; validation successful"')
obvious['.env'] = 'APP_ENV=production\nLOCAL_DATA_DIR=/home/alice/company/state\n'

subtle = deepcopy(BASE)
subtle['.github/workflows/ci.yml'] = CI.replace('      - run: python -m unittest discover -s tests',
    '      - name: Unit tests\n        continue-on-error: true\n        run: python -m unittest discover -s tests')
subtle['app.py'] = '''from pathlib import Path

STATE_PATH = "/home/alice/internal/production/state.json"


def load_state():
    """Read the application's persisted state."""
    return Path(STATE_PATH).read_text()


def add(a, b):
    return a + b
'''
subtle['.github/workflows/pr-preview.yml'] = '''name: PR preview
on: [pull_request_target]
permissions:
  contents: write
jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: ${{ github.event.pull_request.head.sha }}
          allow-unsafe-pr-checkout: true
      - run: python app.py
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
'''

healthy = deepcopy(BASE)
healthy['.github/workflows/triage.yml'] = '''name: Label incoming pull requests
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: read
  pull-requests: write
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr edit "$PR_NUMBER" --add-label "needs-review"
        env:
          PR_NUMBER: ${{ github.event.pull_request.number }}
          GH_REPO: ${{ github.repository }}
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
'''

CASES = {
    'obvious': {'files': obvious, 'expected': [
        {'id': 'dependency-conflict', 'files': ['pyproject.toml', 'requirements.txt'], 'keywords': ['conflict', 'inconsisten', 'mismatch', 'different', '2.31.0'], 'max_severity': 'medium'},
        {'id': 'tests-skipped', 'files': ['.github/workflows/ci.yml'], 'keywords': ['test', 'skip'], 'max_severity': 'high'},
        {'id': 'committed-local-environment', 'files': ['.env'], 'keywords': ['environment', 'local', 'path', 'production', 'config'], 'max_severity': 'medium'},
    ]},
    'subtle': {'files': subtle, 'expected': [
        {'id': 'ineffective-test-gate', 'files': ['.github/workflows/ci.yml'], 'keywords': ['error', 'failure', 'fail'], 'max_severity': 'high'},
        {'id': 'privileged-untrusted-pr', 'files': ['.github/workflows/pr-preview.yml'], 'keywords': ['untrusted', 'pull_request_target', 'fork', 'privileg'], 'min_severity': 'high', 'max_severity': 'critical'},
        {'id': 'machine-specific-state-path', 'files': ['app.py'], 'keywords': ['path', 'machine', '/home/alice'], 'max_severity': 'medium'},
    ]},
    'healthy': {'files': healthy, 'expected': []},
}
