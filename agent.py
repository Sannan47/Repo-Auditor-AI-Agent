"""Required unattended command-line entry point."""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from auditor.engine import Trace, run_agent
from auditor.provider import OpenAICompatibleProvider, Settings
from auditor.repository import AuditError, clone_repository, git_command, normalize_url
from auditor.safety import protect_secret, redact
from tools import InspectionTools


def write_report(path: Path, report: dict):
    """Replace the destination only after a complete report has been validated."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".audit-", suffix=".json", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(report, stream, indent=2, ensure_ascii=True, allow_nan=False)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description="LLM-directed, read-only DevOps audit of a public GitHub repository")
    parser.add_argument("--repo", required=True, help="https://github.com/OWNER/REPOSITORY")
    parser.add_argument("--output", required=True, type=Path, help="Destination JSON report")
    parser.add_argument("--trace", type=Path, help="Sanitized JSONL trace; default: OUTPUT.trace.jsonl")
    args = parser.parse_args(argv)
    try:
        url = normalize_url(args.repo)
        try:
            from dotenv import load_dotenv
        except ImportError as exc:
            raise AuditError("Install dependencies with: python -m pip install -r requirements.txt") from exc
        # Load only this project's configuration, never files from the inspected repo.
        load_dotenv(Path(__file__).resolve().parent / ".env", override=False)
        settings = Settings.from_environment()
        protect_secret(settings.api_key)
        output = args.output.resolve()
        trace_path = (args.trace or Path(str(args.output) + ".trace.jsonl")).resolve()
        if output == trace_path:
            raise AuditError("Output and trace paths must be different")
        if not output.parent.is_dir() or not trace_path.parent.is_dir():
            raise AuditError("Output and trace parent directories must already exist")
        provider = OpenAICompatibleProvider(settings)
        with tempfile.TemporaryDirectory(prefix="devops-audit-") as work:
            root = Path(work) / "repository"
            with Trace(trace_path) as trace:
                trace.write("started", repository=url, model=settings.model)
                clone_repository(url, root)
                trace.write("repository_snapshot", commit=git_command(["rev-parse", "HEAD"], cwd=root).strip())
                tools = InspectionTools(root)
                report = run_agent(url, tools, provider, trace, settings.max_rounds)
                write_report(output, report)
        print(f"Audit completed: {len(report['violations'])} violation(s). Report: {output}")
        return 0
    except (AuditError, OSError) as exc:
        print(f"Audit failed: {redact(str(exc))}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Audit interrupted; no completed report was written.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
