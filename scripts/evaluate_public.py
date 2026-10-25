"""Run the exact unattended CLI against public repos and verify its artifacts."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from auditor.coverage import AREAS
from auditor.report import validate_report
from auditor.repository import AuditError, git_command, normalize_url
from auditor.safety import protect_secret, sanitize


def verify_artifacts(repository, report_path, trace_path):
    report = json.loads(report_path.read_text(encoding='utf-8'))
    events = [json.loads(line) for line in trace_path.read_text(encoding='utf-8').splitlines()]
    observed, inspections, coverage, listing_complete = {}, {}, None, False
    for event in events:
        if event['event'] == 'tool_result':
            result = event['result']
            inspections[event['call_id']] = event['turn']
            if event['name'] == 'list_files' and 'error' not in result:
                listing_complete = not result['truncated']
            if event['name'] == 'read_file' and 'error' not in result:
                observed.setdefault(result['path'], set()).update(row['line'] for row in result['lines'])
            if event['name'] == 'read_files' and 'error' not in result:
                for child in result['files']:
                    inspections[child['inspection_id']] = event['turn']
                    if 'error' not in child:
                        observed.setdefault(child['path'], set()).update(row['line'] for row in child['lines'])
            if event['name'] == 'search_code' and 'error' not in result:
                for row in result['matches']:
                    observed.setdefault(row['file'], set()).add(row['line'])
        if event['event'] == 'coverage':
            coverage = event['assessments']
            for assessment in coverage.values():
                if not all(ref in inspections and inspections[ref] < event['turn'] for ref in assessment['evidence_calls']):
                    raise AuditError('Saved coverage cites nonexistent or uninterpreted evidence')
    if not coverage or set(coverage) != set(AREAS):
        raise AuditError('A completed audit must preserve all nine area assessments')
    if events[-1]['event'] != 'completed' or events[-1]['report'] != report:
        raise AuditError('Report and completed trace do not match')
    verified = validate_report(report, repository, SimpleNamespace(observed=observed, listing_complete=listing_complete))
    if verified != report:
        raise AuditError('Saved report did not retain its validated JSON contract')
    return {
        'target_commit': next(event['commit'] for event in events if event['event'] == 'repository_snapshot'),
        'model_turns': max(event.get('turn', 0) for event in events),
        'finding_count': len(report['violations']), 'coverage': coverage,
        'tool_errors': [{'turn': event['turn'], 'tool': event['name'], 'error': event['result']['error']}
                        for event in events if event['event'] == 'tool_result' and 'error' in event['result']],
    }


def audit(repository, output, timeout):
    slug = repository.removeprefix('https://github.com/').replace('/', '__')
    report_path, trace_path = output / (slug + '.json'), output / (slug + '.trace.jsonl')
    started = time.monotonic()
    record = {'repository': repository, 'report': report_path.name, 'trace': trace_path.name}
    print(f'Starting {repository}', flush=True)
    try:
        process = subprocess.run([sys.executable, str(ROOT / 'agent.py'), '--repo', repository,
                                  '--output', str(report_path), '--trace', str(trace_path)],
                                 cwd=ROOT, capture_output=True, text=True, encoding='utf-8',
                                 errors='replace', timeout=timeout)
        record.update(exit_code=process.returncode, status='failed', stderr=process.stderr.strip())
        if process.returncode == 0:
            record.update(verify_artifacts(repository, report_path, trace_path), status='completed')
    except subprocess.TimeoutExpired:
        record.update(status='timed_out', exit_code=None, stderr=f'CLI exceeded {timeout} seconds')
    except (AuditError, OSError, ValueError, KeyError) as exc:
        record.update(status='invalid_artifacts', exit_code=None, stderr=str(exc))
    record['seconds'] = round(time.monotonic() - started, 2)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', action='append', required=True)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'tmp/public-evaluation')
    parser.add_argument('--workers', type=int, choices=(1, 2, 3), default=1)
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    try:
        repositories = list(dict.fromkeys(normalize_url(url) for url in args.repo))
        if args.timeout < 1:
            raise AuditError('Timeout must be positive')
        from dotenv import load_dotenv
        import os
        load_dotenv(ROOT / '.env', override=False)
        protect_secret(os.getenv('LLM_API_KEY', ''))
        output = args.output_dir.resolve()
        output.mkdir(parents=True, exist_ok=True)
        summary = {'agent_commit': git_command(['-c', f'safe.directory={ROOT}', 'rev-parse', 'HEAD'], cwd=ROOT).strip(),
                   'note': 'Completion and artifact checks are automated; finding correctness requires source review. No public repo is assumed defect-free.',
                   'results': []}
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(audit, repository, output, args.timeout) for repository in repositories]
            for future in as_completed(futures):
                record = sanitize(future.result())
                summary['results'].append(record)
                (output / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
                print(f"{record['repository']}: {record['status']}, findings={record.get('finding_count')}, turns={record.get('model_turns')}, seconds={record['seconds']}", flush=True)
        return int(any(record['status'] != 'completed' for record in summary['results']))
    except (AuditError, OSError) as exc:
        print(sanitize(str(exc)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
