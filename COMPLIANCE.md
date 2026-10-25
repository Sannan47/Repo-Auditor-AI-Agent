# Assignment requirement verification

Reviewed against all three pages of the local Assignment 2 handout after the
secret-redaction and investigation-coverage fixes. The PDF and private `.env`
remain local, ignored files. This matrix documents verification; the executable
agent and authentic JSON report are the submission artifacts.

| Requirement | Implementation and evidence |
| --- | --- |
| Python; public GitHub URL accepted automatically | `agent.py`, URL validation and temporary HTTPS clone in `auditor/repository.py`; authentic public-repository audit in `examples/sample_trace.jsonl`. |
| Observe, reason, select tools, execute, interpret, report | Explicit loop in `auditor/engine.py`; LLM chooses tools, batches, follow-ups and conclusions. Inspection outputs and visible evidence IDs return to the LLM. |
| Not a static scanner followed by an LLM summary | Tools return content, not precomputed violations. Coverage records scope and evidence eligibility, not defect rules. Authentic traces show LLM-directed investigations and corrections. |
| No prohibited orchestration framework | Only a basic provider SDK and dotenv are dependencies. Loop, dispatch, control flow and validation are implemented directly in Python. |
| Four required inspection tools | `tools.py` implements `list_files`, `read_file`, `search_code`, and `git_log`; tool tests cover their actual local Git behavior. |
| All nine DevOps inspection areas | `auditor/coverage.py` and `record_assessments` require evidence-linked repository hygiene, dependencies, code quality, testing, CI, security, configuration, collaboration and build/release conclusions. All three live fixtures and the public sample have nine assessments. |
| Genuine findings, alternatives, remediation | LLM investigation and final review; live fixtures detect six injected issues and leave a healthy library with equivalent configurations and safe PR labeling clean. No blanket requirement for optional tools or application lockfiles. |
| No inference of remote branch protection | Explicit system instructions prohibit it; no tool claims to inspect those remote settings. |
| DevOps-only scope | Prompt excludes ML training, datasets, model validation, experiment tracking and other MLOps-specific investigations. Fixture evaluation tests DevOps detection, not ML training. |
| Exact CLI; unattended | `python agent.py --repo URL --output report.json`; no interactive prompts. Real public audit and mocked complete CLI test both succeed. |
| Exact report structure and severity values | `auditor/report.py` validates all required fields, allowed severity values, nullable locations and observed positive line numbers, both before and after sanitization. No coverage fields are added to report JSON. |
| Empty violations array when no defensible findings | Genuine public sample and healthy live fixture both produce an empty array after content investigation and final review. |
| Useful nonzero fatal errors | Invalid input, missing configuration/files, Git/API errors, timeouts and exhausted budgets are handled. Existing reports are replaced atomically only on successful completion. |
| Target remains unchanged; safe execution | Temporary clone, read-only allowlisted inspection commands, no target source/test/build execution, no submodule recursion, no inherited Git hooks/filters. Tests verify unchanged file contents and Git status. Optional target test/lint execution tools are not required and are intentionally omitted. |
| Secrets do not appear in supported output paths | Whole-file credential redaction before line pagination/search and Git-history truncation; PEM/YAML/triple-quote/delimiter/echo regressions; configured key protected in errors/traces. Protocol keys and severity enums remain intact. README records the limits of heuristic format recognition. |
| No invented unavailable results | Errors and truncation are explicit. An `unavailable` area must cite an actual failed/truncated check; a listing alone cannot establish a clean nonempty repository. No claims of executed test outcomes. |
| No hardcoded target findings or hidden answers | Production agent does not import fixture labels. Labels live only in the opt-in evaluator and tests; instructor repositories and answers are unavailable. |
| Evidence, severity, duplicate handling | Observed location validation, sanitized excerpts, impact-calibrated prompt and final review; duplicate-ID/location and description/location filtering; evaluator flags duplicated/unexpected findings and severity issues. Semantic correctness remains an LLM responsibility. |
| Required submission files | `agent.py`, `tools.py`, `auditor/`, `requirements.txt`, `.env.example`, `README.md`, `tests/`, authentic `sample_report.json` are included. Additional traces, fixtures and this matrix support review. |
| Evaluator can install and configure | README gives Python/Git prerequisites, virtual environment activation, dependency installation, local API configuration and exact command. CI installs dependencies and runs checks on Python 3.12 and 3.13. |
| Tests and precision/recall evaluation | Automated regression and orchestration suite; opt-in `scripts/evaluate_fixtures.py` runs obvious, subtle and healthy synthetic repositories. Counts and fixture precision/recall follow the assignment formulas. Inspect unexpected findings manually; these are not hidden-evaluation scores. |
| Public GitHub submission, not a ZIP or handwritten substitute | Public repository contains executable implementation and authentic reports/traces. Submit its single repository URL through the course submission channel; that final course action remains with the student. |

## Observed verification and practical limits

- Both reported bugs have explicit regressions: multiline credential bodies cannot
  escape through paginated reads/searches/traces, and secret words cannot rename
  report keys or mutate severity enums. Sanitized reports are validated again.
- Coverage regressions reject listing-only reports, empty-page pseudo-inspections,
  unread manifests/workflows, fabricated or uninterpreted evidence references,
  and unsupported unavailable-check claims.
- Live fixtures found all six labeled defects with no extra findings or severity
  violations. The expanded healthy case returned zero findings. Reports and
  nine-area assessments are preserved in `examples/evaluation/`.
- The real public-repository sample inspected commit
  `42d24b8bb81eca3894b5f4e5a9d54e529d8eac29`, including `requirements.txt`, and
  completed all nine areas in eight model turns. It is unedited agent output.
- The Windows host cannot create test symlinks without privileges, so that one
  local test skips; Linux CI runs the same test. No instructor grade or unseen
  repository accuracy is claimed. Coverage bookkeeping proves evidence was
  inspected, not exhaustive semantic understanding of every file or secret format.
