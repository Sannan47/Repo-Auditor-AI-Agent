# DevOps Repository Auditing Agent

An explicit Python LLM/tool agent that investigates public GitHub repositories and
writes evidence-based DevOps findings as JSON. The LLM selects inspection tools and
follow-up calls; Python implements dispatch, limits, validation, and reporting.
No agent or orchestration framework is used.

## Installation

Requires Python 3.12+ and Git on PATH. Public target repositories need no GitHub token.

```bash
git clone https://github.com/Sannan47/Repo-Auditor-AI-Agent.git
cd Repo-Auditor-AI-Agent
python -m venv .venv
```

Activate on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Activate on Linux/macOS:

```bash
source .venv/bin/activate
```

Then install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Gemini configuration

Create a Gemini API key in [Google AI Studio](https://aistudio.google.com/apikey).
API project quotas/billing are separate from Gemini app plan access. Free-tier
availability and quotas depend on the project; a consumer subscription does not
establish this application's API quota.

Copy `.env.example` to `.env`:

```powershell
Copy-Item .env.example .env
```

Or on Linux/macOS:

```bash
cp .env.example .env
```

Set `LLM_API_KEY` in `.env`. The other supplied settings are:

```dotenv
LLM_MODEL=gemini-3.1-flash-lite
LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/
AGENT_MAX_ROUNDS=30
LLM_TIMEOUT_SECONDS=60
```

The basic OpenAI Python SDK sends requests to Google's documented
[OpenAI-compatible Gemini endpoint](https://ai.google.dev/gemini-api/docs/openai).
This is a provider SDK, not an agent framework. No OpenAI account or key is needed
for this Gemini configuration. The endpoint and model are configurable; use a
model that supports Chat Completions function calls.

Gemini 3.1 Flash-Lite is the tested default. During integration, the newer 3.8 Flash
model returned service errors and 2.5 Flash was unavailable to a new API project;
the default therefore follows actual successful API access, not model-list metadata.

Environment variables override `.env`. Only the `.env` beside `agent.py` is loaded;
the target repository's environment files are never loaded. `.env`, virtual
environments, generated audit reports/traces, and the local assignment PDF are ignored
by Git. `.env.example` contains variable names and nonsecret settings only.

## Execution

```bash
python agent.py --repo https://github.com/OWNER/REPOSITORY --output report.json
```

Runs unattended. Existing output/trace parent directories must exist. Exit code 0
means a completed, validated report; fatal errors return 1 and a useful stderr message.
Invalid CLI arguments return 2. Interruptions return 130. A failed audit does not
replace an existing report; check the exit code rather than assuming an older output
file is from the latest run. Successful JSON is replaced atomically.

By default, a sanitized trace is written to `report.json.trace.jsonl`. Override it:

```bash
python agent.py --repo https://github.com/OWNER/REPOSITORY --output report.json --trace audit.trace.jsonl
```

Trace events record model decisions/tool selections, tool results, and the completed
report. They allow inspection of genuine dynamic behavior. They contain brief
investigation explanations, not private chain-of-thought. Traces can remain after
failed runs to help diagnose incomplete inspections.

## Architecture

`agent.py` validates configuration, clones the target into a temporary directory,
starts the loop, writes validated JSON, and cleans up the clone.

`auditor/engine.py` implements the cycle directly:

1. Observe the repository URL and previous tool results.
2. Ask the LLM to interpret observations and choose tools, with a brief reason.
3. Dispatch only allowlisted tools with validated arguments.
4. Return sanitized outputs or explicit errors to the LLM.
5. Let the LLM select follow-up investigations.
6. Validate the candidate `submit_report` JSON and cited locations. Return invalid
   reports for correction. Require a final LLM evidence review to challenge
   unsupported claims, allow further tool calls, and then accept a reviewed report.

`tools.py` implements the four required tools:

| Tool | Behavior |
| --- | --- |
| `list_files()` | Lists tracked file paths, including dotfiles, with explicit truncation metadata. |
| `read_file(path)` | Returns numbered lines; optional `start_line`/`end_line` support follow-up reads. |
| `search_code(pattern)` | Case-insensitive **literal substring** search, with file/line evidence and skipped-file metadata. |
| `git_log()` | Latest 30 commit subjects/dates from a shallow clone of up to 100 commits. |

`auditor/provider.py` handles only basic LLM requests and configuration.
`auditor/report.py` validates the exact report contract, observed locations, and
duplicate IDs/descriptions at a location. Semantic evidence interpretation and
combining related root causes are the LLM's responsibilities, not guarantees of
schema validation. `auditor/safety.py` redacts credential-like values.

## Inspection scope and evidence

The agent investigates repository hygiene, dependency management, code quality,
testing, GitHub Actions/CI, security, configuration, collaboration, and build/release.
ML training, datasets, model validation, experiment tracking, and other MLOps matters
are excluded.

The instructions require checking equivalent solutions before treating absent
optional files/tools as defects, distinguishing placeholders from credentials,
calibrating severity, combining duplicates, and checking surrounding context.
Remote branch protection is not inferred from repository files. A finding must
cite an inspected file/line or use JSON null for inapplicable locations. Repository
absence findings require a complete file listing. A clean completed inspection
returns an empty `violations` array.

The report contains exactly `repository` and `violations`. Every violation contains
`rule_id`, `category`, `severity`, `file`, `line`, `description`, `evidence`, and
`recommendation`. Severity is `critical`, `high`, `medium`, or `low`; `line` is a
1-based integer or null. Secret values must never appear in evidence.

## Safety and limits

- Targets are cloned into a temporary directory and inspected without modification.
  No source, tests, build scripts, package installs, hooks, or workflows from targets
  are executed. There is no shell-execution tool. These text inspections cannot prove
  tests pass/fail or establish actual remote Actions/branch-protection state.
- Clone transport is restricted to HTTPS GitHub owner/repository URLs. Git ignores
  inherited/global/system configuration, disables hooks and credential prompts,
  and does not recurse into submodules. Clone timeout: 120 seconds; Git tool timeout:
  30 seconds. Git must be kept up to date on the host.
- Reads reject traversal, `.git` access, symbolic links and junctions. Binary files
  and files above 512,000 bytes are skipped with explicit errors. Listings inspect at
  most 10,000 paths; reads/searches bound returned content to approximately 32,000
  characters; searches return at most 100 matches. Oversized files are not silently
  declared safe. Submodule contents and LFS payloads are not fetched.
- At most eight tools per model turn and 30 model turns by default; the configurable
  maximum is 100. Budget exhaustion fails rather than inventing a successful report.
  SDK requests have a configurable timeout and two retries for retryable failures.
- Repository content is explicitly treated as untrusted data, including instructions
  aimed at AI agents. Prompt defenses and heuristic credential redaction reduce risk
  but cannot guarantee detection of every adversarial instruction or secret format.
  Tool outputs are redacted before reaching the provider, traces, or report.
  Whole-file redaction handles PEM private keys, YAML credential blocks, and
  triple-quoted credentials before splitting text into numbered lines. Protocol
  keys and severity enum values are preserved, and sanitized reports are validated
  again before acceptance.
- Detection quality depends on the model, inspected content, available context and
  limits. No access to instructor hidden repositories or answer keys is assumed.

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests run without real API credentials. They exercise actual local Git fixtures and
a scripted provider for deterministic loop checks. Scripted responses test orchestration,
not LLM detection quality; real model audits must be checked separately. CI executes
the suite on Python 3.12 and 3.13 using read-only permissions and pinned Actions.

## Authentic sample

`sample_report.json` is unedited output from a real Gemini 3.1 Flash-Lite audit on
October 25, 2026:

```bash
python agent.py --repo https://github.com/Sannan47/Repo-Auditor-AI-Agent --output sample_report.json
```

The inspected repository commit was
`a9d5d53c8d05ddc9d536f19ad0411c6b3090ae21`. The run completed in 14 model turns,
including follow-up inspections and final evidence review. The resulting violations
array is empty. This records that run's conclusions, not a guarantee that the
repository is defect-free. `examples/sample_trace.jsonl` preserves its actual
sanitized decisions and tool outputs, including the target commit. Repeating the
command audits the current default branch, so content and findings can differ.

A separate live check used a temporary synthetic Git repository whose CI test step
had `continue-on-error: true`. The agent identified that ineffective test gate and
retained the finding after review. These limited live checks do not estimate
precision or recall on the instructor's hidden repositories.
