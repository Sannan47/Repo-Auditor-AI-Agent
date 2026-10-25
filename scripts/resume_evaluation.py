"""Resume a failed evaluation without paying again for its unchanged inspections.

This is an opt-in evaluation helper, not a replacement for the assignment CLI.
Only actual saved assistant decisions are replayed. Inspection tools run again,
and their results must match the original trace at the identical Git commit.
After the first old submission, all further decisions come from the live model.
"""

import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent import write_report
from auditor.engine import Trace, run_agent
from auditor.provider import OpenAICompatibleProvider, Settings
from auditor.repository import AuditError, clone_repository, git_command
from auditor.safety import protect_secret, sanitize
from tools import InspectionTools


def replay_prefix(events):
    messages = []
    for event in events:
        if event['event'] != 'decision':
            continue
        message = event['message']
        messages.append(message)
        if any(call['function']['name'] == 'submit_report' for call in message.get('tool_calls', [])):
            break
    if not messages:
        raise AuditError('Resume trace has no saved model decisions')
    return messages


class ReplayProvider:
    def __init__(self, messages, live, trace):
        self.messages, self.live, self.trace = iter(messages), live, trace

    def complete(self, messages, definitions):
        try:
            saved = next(self.messages)
        except StopIteration:
            return self.live.complete(messages, definitions)
        self.trace.write('replayed_decision', provenance='saved model output; no new API call')
        return deepcopy(saved)

    def drain_retry_events(self):
        return self.live.drain_retry_events()


class VerifiedTrace(Trace):
    def __init__(self, path, original):
        super().__init__(path)
        self.original = {e['call_id']: e for e in original if e['event'] == 'tool_result'
                         and e['name'] in {'list_files', 'read_file', 'read_files', 'search_code', 'git_log'}}

    def write(self, event, **data):
        if event == 'tool_result' and data.get('call_id') in self.original:
            expected = self.original.pop(data['call_id'])
            if sanitize(data['result']) != expected['result']:
                raise AuditError('Replayed inspection differs from the saved observation; refusing to resume')
        super().write(event, **data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / '.env', override=False)
        settings = Settings.from_environment()
        protect_secret(settings.api_key)
        if args.trace.stat().st_size > 32 * 1024 * 1024:
            raise AuditError('Resume trace exceeds 32 MiB')
        events = [json.loads(line) for line in args.trace.read_text(encoding='utf-8').splitlines()]
        started = next(e for e in events if e['event'] == 'started')
        commit = next(e['commit'] for e in events if e['event'] == 'repository_snapshot')
        if started['model'] != settings.model:
            raise AuditError('Resume requires the same configured model')
        output = args.output.resolve()
        trace_path = Path(str(output) + '.trace.jsonl')
        if args.trace.resolve() in {output, trace_path} or not output.parent.is_dir():
            raise AuditError('Use a new output path in an existing directory')
        with tempfile.TemporaryDirectory(prefix='audit-resume-') as work:
            root = Path(work) / 'repository'
            clone_repository(started['repository'], root)
            if git_command(['rev-parse', 'HEAD'], cwd=root).strip() != commit:
                raise AuditError('Repository commit changed; a fresh audit is required')
            with VerifiedTrace(trace_path, events) as trace:
                trace.write('started', repository=started['repository'], model=settings.model)
                trace.write('repository_snapshot', commit=commit)
                trace.write('resumed_from', source_trace=args.trace.name,
                            mode='verified inspection replay followed by live model decisions')
                provider = ReplayProvider(replay_prefix(events), OpenAICompatibleProvider(settings), trace)
                report = run_agent(started['repository'], InspectionTools(root), provider, trace, settings.max_rounds)
                write_report(output, report)
        print(f'Resumed audit completed: {len(report["violations"])} findings; {output}')
        return 0
    except (AuditError, OSError, ValueError, KeyError, StopIteration) as exc:
        print(sanitize(str(exc)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
