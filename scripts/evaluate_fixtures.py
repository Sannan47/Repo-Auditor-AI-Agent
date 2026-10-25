"""Opt-in live-model detection evaluation on local, nonexecuted synthetic repos."""

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))

from auditor.engine import Trace, run_agent
from auditor.provider import OpenAICompatibleProvider, Settings
from auditor.repository import AuditError, git_command
from auditor.safety import protect_secret, sanitize
from fixture_cases import CASES
from tools import InspectionTools


def make_fixture(root, case):
    root.mkdir()
    for name, content in case['files'].items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
    git_command(['init', '--quiet', str(root)])
    # The deliberately committed .env in the synthetic case contains NO API key.
    git_command(['add', '-f', '.'], cwd=root)
    git_command(['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 'commit', '-qm', 'Synthetic repository fixture'], cwd=root)


def score(case, report):
    matched, unexpected, severity_issues = {}, [], []
    ranks = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
    for finding in report['violations']:
        text = (finding['description'] + ' ' + finding['evidence']).lower()
        match = next((label for label in case['expected'] if label['id'] not in matched
                      and finding['file'] in label['files']
                      and any(word.lower() in text for word in label['keywords'])), None)
        if match:
            matched[match['id']] = finding
            rank = ranks.get(finding.get('severity'), 0)
            if rank > ranks.get(match.get('max_severity', 'critical'), 3) or rank < ranks.get(match.get('min_severity', 'low'), 0):
                severity_issues.append({'id': match['id'], 'severity': finding.get('severity')})
        else:
            unexpected.append(finding)
    return {'matched': list(matched), 'missed': [label['id'] for label in case['expected'] if label['id'] not in matched],
            'unexpected_findings_for_review': unexpected, 'severity_issues': severity_issues}


def metrics(results):
    reported = sum(len(result['report']['violations']) for result in results.values())
    matched = sum(len(result['matched']) for result in results.values())
    expected = sum(len(result['matched']) + len(result['missed']) for result in results.values())
    return {'reported': reported, 'matched': matched, 'expected': expected,
            'precision': matched / reported if reported else None,
            'recall': matched / expected if expected else None,
            'scope': 'Synthetic fixture labels only; heuristic matches and unexpected findings require evidence review.'}


def evaluate(names, output, settings):
    output.parent.mkdir(parents=True, exist_ok=True)
    results = {}
    provider = OpenAICompatibleProvider(settings)
    for name in names:
        print(f'Evaluating {name} (live API calls; target code is never executed)', flush=True)
        with tempfile.TemporaryDirectory(prefix='auditor-evaluation-') as work:
            root = Path(work) / 'repository'
            make_fixture(root, CASES[name])
            trace_path = output.parent / f'{name}.trace.jsonl'
            with Trace(trace_path) as trace:
                report = run_agent(f'https://github.com/example/synthetic-{name}', InspectionTools(root), provider, trace, settings.max_rounds)
            results[name] = {'report': report, **score(CASES[name], report)}
            events = [json.loads(line) for line in trace_path.read_text(encoding='utf-8').splitlines()]
            results[name]['coverage'] = next(event['assessments'] for event in reversed(events) if event['event'] == 'coverage')
        output.write_text(json.dumps(sanitize({'model': settings.model, 'cases': results, 'metrics': metrics(results)}), indent=2), encoding='utf-8')
        print(f"{name}: matched={len(results[name]['matched'])}, missed={results[name]['missed']}, unexpected={len(results[name]['unexpected_findings_for_review'])}, severity_issues={results[name]['severity_issues']}", flush=True)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', action='append', choices=list(CASES))
    parser.add_argument('--output', type=Path, default=ROOT / 'tmp/evaluation/results.json')
    args = parser.parse_args()
    from dotenv import load_dotenv
    load_dotenv(ROOT / '.env', override=False)
    try:
        settings = Settings.from_environment()
        protect_secret(settings.api_key)
        results = evaluate(args.case or list(CASES), args.output, settings)
        # Matching is a transparent heuristic; inspect actual evidence before
        # interpreting unexpected findings as false positives.
        return int(any(result['missed'] or result['unexpected_findings_for_review'] or result['severity_issues'] for result in results.values()))
    except (AuditError, OSError) as exc:
        print(sanitize(str(exc)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
