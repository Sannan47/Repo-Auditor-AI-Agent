# Public repository validation — October 25, 2026

**Status: operational checks complete for two deliberately vulnerable repositories;
semantic detection checks failed. This is not a submission-readiness sign-off.**

The exact unattended CLI was run through `scripts/evaluate_public.py`. Targets
were cloned and inspected read-only; target code, builds and tests were not run.
The latest completed pair used agent commit
`dfedfcf3885e42ca9089e1ab6effdb3f22598ff9` and `gemini-3.1-flash-lite`.
Both reports passed JSON, observed-location, trace-completion and nine-area
evidence checks. Those checks do not establish that findings are correct.

| Target and inspected commit | Completed result | Manual source review |
| --- | --- | --- |
| [StepSecurity GitHub Actions Goat](https://github.com/step-security/github-actions-goat/tree/4da23c8602b4589bacdf7de77240113e02cdb884) | 19 model turns; 3 findings | Correctly identified the derived GCP private key printed by `.github/workflows/secret-in-build-log.yml:29`. A token-permissions claim was unsupported by inherited remote settings; the TOCTOU finding overstated code execution where the shown commands only read repository content. Rejected as a fully correct report. |
| [Bridgecrew TerraGoat](https://github.com/bridgecrewio/terragoat/tree/729f8da62c6a85ce4af5ad3d123de97776d954c4) | 12 model turns; 1 finding | Incorrectly treated Git commit attribution as authentication. Omitted concrete infrastructure defects, including broad IAM actions/resources and plaintext credentials in EC2 user data. Rejected as a correct report. |

These projects intentionally contain unsafe configurations for teaching. That
context explains their purpose; it does not make active unsafe configurations
safe to deploy. Conversely, comments labelling something vulnerable do not prove
a current vulnerability. Review must establish behavior from actual source and
current defaults. No claim is made that the demo credentials are live.

Earlier ordinary-repository smoke runs completed for `pallets/itsdangerous`,
`sindresorhus/is`, and `cli/safeexec`, returning zero findings. These were
completion checks without an exhaustive ground truth. Attempts against
`psf/requests` and `BurntSushi/ripgrep` encountered provider throttling and do not
count as successful completed audits.

## Stronger-model attempt and remaining work

Both vulnerable targets were subsequently attempted with `gemini-3.6-flash`.
Neither produced a completed report because the API exhausted its daily quota.
A separate minimal request confirmed HTTP 429 with quota ID
`GenerateRequestsPerDayPerProjectPerModel-FreeTier`, quota value `20`, and a
retry delay of `74014s` at the time of the check. No billing or API project settings
were changed. A consumer Gemini subscription does not establish this API project's
available quota.

The compatibility endpoint returned a **list** of error envelopes. Provider
handling now recognizes this format and stops immediately on daily/zero quota,
with regressions for daily quota, transient retry metadata and malformed input.

Raw local attempts remain under the ignored `tmp/` directory:
`public-baseline`, `vulnerable-bulk-final`, and `vulnerable-gemini36`. Rejected
reports have not replaced the authentic historical sample report.

Additional requested model checks on the same day:

- `gemini-2.0-flash` returned HTTP 404; it was not configured as the default.
- `gemini-3.8-flash` failed a short request without an HTTP response, then returned
  HTTP 503 on a second check with a 60-second timeout.
- `gemini-3-flash-preview` answered a minimal request and was used for both exact
  CLI audits (`tmp/vulnerable-gemini3`). GitHub Actions Goat failed at turn 4 after
  five HTTP 503 attempts. TerraGoat reached turn 7, then failed on explicit daily
  or zero project quota. Neither attempt produced a completed report. These
  checks therefore do not establish reliable audit availability for either model.

Before calling the project ready, rerun both targets with sufficient API quota
and a model that demonstrates reliable evidence interpretation, review every
finding and the known omissions, and rerun the synthetic evaluation on the current
fixture revision. The saved `examples/evaluation/` results are historical; the
unsafe-checkout fixture has since been made explicit about opting out of modern
checkout protections. Its previous metrics must not be represented as a fresh
evaluation of the current revision. No score on unseen instructor repositories
can be guaranteed.
