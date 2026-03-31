# konflux-ci-scanner

Scans the `konflux-ci` GitHub organization to identify repositories that have:

1. **AI PR review tools** enabled (CodeRabbit, Qodo/PR-Agent, Gemini Code Assist)
2. **CI enabled with JUnit/test results** available (Konflux/Tekton pipelines or OpenShift CI)

## Requirements

- Python 3.10+
- No external dependencies (uses only the Python standard library)

## Usage

```bash
# Basic scan (unauthenticated, 60 API requests/hour limit)
python3 scan.py

# With a GitHub token for higher rate limits (5000 req/hr)
python3 scan.py --github-token ghp_xxxxx
# or
export GITHUB_TOKEN=ghp_xxxxx
python3 scan.py

# Output as JSON
python3 scan.py --format json --output results.json

# Output as CSV
python3 scan.py --format csv --output results.csv

# Verbose logging
python3 scan.py --verbose

# Scan a different org
python3 scan.py --org my-org
```

## What it detects

### AI PR Review Tools

| Tool | Detection Method |
|------|-----------------|
| **CodeRabbit** | `.coderabbit.yaml` in repo root; also checks `{org}/coderabbit` repo for org-wide config |
| **Qodo / PR-Agent** | `.pr_agent.toml` in repo root; GitHub Actions workflows referencing `qodo-ai/pr-agent` or `codiumai/pr-agent`; also checks `{org}/pr-agent-settings` repo |
| **Gemini Code Assist** | `.gemini/config.yaml` or `.gemini/styleguide.md` in repo |

With `--github-token`, the script also searches PR comment history for bot
activity (`coderabbitai[bot]`, `qodo-code-review[bot]`, `gemini-code-assist[bot]`).
This catches tools installed as GitHub Apps with default settings (no config file).
Without a token, only config-file detection is available.

### CI with JUnit/Test Results

| CI System | Detection Method | JUnit Availability |
|-----------|-----------------|-------------------|
| **Konflux (Tekton)** | `.tekton/` directory with pipeline YAML files | Build pipelines include scanning tasks (clair-scan, clamav-scan, etc.) that produce `TEST_OUTPUT` results and attach SARIF/scan results to OCI images via `oras attach` |
| **OpenShift CI** | Checks `openshift/release` repo for `ci-operator/config/`, `ci-operator/jobs/`, `core-services/prow/02_config/` directories for the org | ci-operator inherently produces `junit_operator.xml` and collects all `junit*.xml` files from `$ARTIFACT_DIR` |

## API Usage

The script uses a hybrid strategy to minimize GitHub API calls:

- **GitHub API** (`api.github.com`): Used to list org repos, fetch repo trees,
  and check OpenShift CI config in `openshift/release`. Subject to rate limits.
- **Raw content** (`raw.githubusercontent.com`): Used to check for specific
  config files. Not subject to the API rate limit.

Unauthenticated API budget: ~60 requests/hour. A typical scan of ~150 repos
uses approximately:
- 2 API calls to list repos
- ~150 API calls for .tekton/ directory listings (one per repo)
- 3 API calls for OpenShift CI batch checks

With a token (recommended), the 5,000 req/hr limit is more than sufficient,
and the PR comment search feature is enabled (3 additional search API calls).

## Results

See [RESULTS.md](RESULTS.md) for the latest scan output.

## Output Formats

- **text** (default): Human-readable report with summary and categorized lists
- **json**: Machine-readable JSON array of repo objects
- **csv**: Spreadsheet-friendly CSV with boolean columns
