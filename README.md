# DevOps Repository Auditing Agent

A Python agent that investigates public GitHub repositories and produces DevOps
findings as JSON. The LLM selects tools and follow-up investigations; an explicit
Python loop handles execution, evidence, validation, and reporting. No agent or
orchestration framework is used.

## Installation

Requires Python 3.12+ and Git on PATH.

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

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Configuration

Copy `.env.example` to `.env` (`Copy-Item .env.example .env` in PowerShell, or
`cp .env.example .env` on Linux/macOS). Set the key, model, and matching API endpoint.
The supplied Gemini configuration is:

```dotenv
LLM_API_KEY=<your Gemini API key>
LLM_MODEL=gemini-3.1-flash-lite
LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/
AGENT_MAX_ROUNDS=30
LLM_TIMEOUT_SECONDS=60
LLM_MAX_RETRIES=4
LLM_RETRY_BASE_SECONDS=5
```

Create a Gemini key in [Google AI Studio](https://aistudio.google.com/apikey).
API quotas are separate from consumer Gemini subscriptions.

The same basic OpenAI Python SDK also supports other Chat Completions endpoints
with function calling. For OpenRouter, use an OpenRouter key and replace the model
and endpoint, for example:

```dotenv
LLM_API_KEY=<your OpenRouter API key>
LLM_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free
LLM_BASE_URL=https://openrouter.ai/api/v1
```

Use a key issued by the selected provider. Model availability and free quotas can
change; check the provider's current account limits. Completed reports have been
obtained with Gemini Flash-Lite and this Nemotron endpoint, but detection errors
were observed with both. No model is presented as a guarantee of audit accuracy.
No OpenAI account is required for either configuration above.

Environment variables override `.env`. Only this project's `.env` is loaded;
configuration from the target is never loaded. Real credentials, virtual
environments, generated artifacts, and the assignment PDF are ignored by Git.

## Execution

```bash
python agent.py --repo https://github.com/OWNER/REPOSITORY --output report.json
```

This runs unattended and needs no GitHub token for public repositories. Output
parent directories must already exist. A successful run atomically writes the
report and exits 0. Fatal errors exit 1, invalid CLI arguments exit 2, and an
interruption exits 130. A failed run leaves an existing report unchanged, so always
check the exit code before treating an output as current.

A sanitized trace is written to `report.json.trace.jsonl` by default. Override it
with `--trace audit.trace.jsonl`. It records brief decisions, actual tool calls and
results, coverage assessments, and completion. A trace can remain after failure;
it is not itself a completed report.

## Architecture and tools

`agent.py` validates configuration and the GitHub URL, clones into a temporary
directory, runs the agent, writes validated JSON, and cleans up the clone.
`auditor/engine.py` implements the observe/reason/select/execute/interpret/report
loop directly. Each model turn receives tool results and an evidence ledger and
chooses its own next investigations.

| Inspection tool | Behavior |
| --- | --- |
| `list_files()` | Lists tracked paths, including dotfiles, with truncation metadata. |
| `read_file(path)` | Returns numbered lines; supports page follow-ups. |
| `search_code(pattern)` | Case-insensitive literal substring search with file/line evidence. |
| `git_log()` | Latest 30 commit subjects/dates from a shallow clone of up to 100 commits. |
| `read_files(paths)` | Bounded initial pages for up to eight files, with separate evidence IDs. |
| `read_action_metadata(action)` | Reads public action metadata at its referenced revision without executing it. |

The first four tools are the assignment's required tools. The model also uses
`record_assessments` to record evidence-linked conclusions for all nine areas:
repository hygiene, dependencies, code quality, testing, CI, security,
configuration, collaboration, and build/release. ML training, datasets, model
validation, and experiment tracking are outside scope.

`auditor/coverage.py` checks inspection prerequisites and references, including
recognized dependency manifests and CI workflows. It does not generate findings
or choose inspection order. Listing-only conclusions and invented evidence IDs
are rejected; unavailable checks require an actual failed or truncated observation.

Once coverage is complete, the model submits a candidate report. A fresh LLM
context receives primary observations and reviews the candidate for unsupported
claims and omissions, with further tools available. `auditor/report.py` checks
schema, observed locations, severity values, duplicates, and sanitized output.
The provider adapter handles requests and bounded retries. Credential redaction
is implemented in `auditor/safety.py`.

## Report contract

The report contains exactly `repository` and `violations`. Each violation has:

- `rule_id`, `category`, and `severity` (`critical`, `high`, `medium`, or `low`).
- `file` and `line`: an inspected relative path and 1-based line, or JSON null
  when inapplicable.
- `description`, sanitized `evidence`, and an actionable `recommendation`.

A completed inspection can return an empty `violations` array. Schema and location
checks establish structural validity and observed locations; they cannot establish
that an LLM's interpretation is correct.

## Safety and operational limits

Targets are inspected read-only. Their code, tests, package installations, build
scripts, hooks, and workflows are never executed. Git transport is restricted to
HTTPS GitHub repository URLs; inherited Git configuration, hooks, credential
prompts, and submodule recursion are disabled. Reads reject traversal, `.git`
access, symlinks, and junctions.

Files above 512,000 bytes and binary files produce explicit inspection errors.
Listings are capped at 10,000 paths, read/search outputs at approximately 32,000
characters, and searches at 100 matches. Submodule contents and LFS payloads are
not fetched. Clone timeout is 120 seconds; Git tool timeout is 30 seconds.

The default budget is 30 model turns with at most eight tools per turn. Exhausting
it fails without inventing a completed report. Transient API/network failures use
bounded retries with backoff; explicit exhausted daily quotas fail promptly.

Repository content is treated as untrusted data. Tool outputs are redacted before
reaching the provider, trace, or report. Whole-file redaction handles common token
formats, private keys, multiline credential assignments, credential URIs, and named
Terraform secret-variable string defaults. Format recognition is heuristic and
cannot guarantee removal of every possible secret or adversarial instruction.

Text inspection cannot prove tests pass, inspect remote branch protection, or
establish inherited workflow permissions. The model is instructed to distinguish
acceptable alternatives, trace actual unsafe behavior, and avoid unsupported CVEs,
remote settings, and optional-tool requirements.

## Tests and evaluation

```bash
python -m unittest discover -s tests -v
```

These tests require no live API key. They use local Git fixtures and scripted model
responses to verify tools, dispatch, follow-ups, coverage, errors, redaction, and
report validation. Scripted responses test orchestration, not detection quality.
CI installs dependencies and runs checks on Python 3.12 and 3.13. The symlink test
can skip on Windows when the host lacks symlink privileges.

Optional live evaluation consumes API quota:

```bash
python scripts/evaluate_fixtures.py
python scripts/evaluate_public.py --repo https://github.com/OWNER/REPOSITORY --output-dir tmp/public-evaluation
```

The synthetic evaluator covers obvious, subtle, and healthy cases. Its labels stay
in the evaluator and are never supplied to the agent. Matching uses explicit file
and keyword rules; precision/recall and unexpected findings need human review.
The public evaluator checks the actual CLI, JSON, trace, and evidence references.
Neither evaluator executes target code.

**Known detection limits:** real audits of StepSecurity's GitHub Actions Goat and
Bridgecrew's TerraGoat completed, but manual review found unsupported findings and
missed defects. Later independent reviews were blocked by provider limits.
Operational completion and nine-area coverage do not imply a semantic pass.
Accuracy on the instructor's hidden repositories has not been established.

## Authentic sample

`sample_report.json` is unedited output from a real Gemini 3.1 Flash-Lite audit on
October 25, 2026, using:

```bash
python agent.py --repo https://github.com/Sannan47/Repo-Auditor-AI-Agent --output sample_report.json
```

The inspected commit was `42d24b8bb81eca3894b5f4e5a9d54e529d8eac29`. The run
completed in eight model turns and returned no violations. This records that run's
conclusions, not a guarantee that the repository is defect-free.
`examples/sample_trace.jsonl` preserves its actual sanitized tool interactions and
all nine area assessments. Repeating the command audits the current default branch.
