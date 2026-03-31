#!/usr/bin/env python3
"""
Scan the konflux-ci GitHub org for repositories that have:
  1. AI PR review tools enabled (CodeRabbit, Qodo/PR-Agent, Gemini Code Assist)
  2. CI enabled with JUnit test results available (Konflux/Tekton or OpenShift CI)

Usage:
    python3 scan.py [--github-token TOKEN] [--org ORG] [--output FILE] [--format {text,json,csv}]

The script works without a GitHub token (unauthenticated), but is subject to
the GitHub API rate limit of 60 requests/hour. With a token, the limit is
5,000 requests/hour.

Strategy:
  - Uses raw.githubusercontent.com for config file checks (no API quota cost)
  - Uses the GitHub Contents API sparingly for directory listings (.tekton/)
  - Checks the openshift/release repo for OpenShift CI configuration (batch)
  - Gracefully handles rate limit exhaustion by skipping remaining API checks
"""

import argparse
import csv
import io
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GITHUB_API = "https://api.github.com"
RAW_GH = "https://raw.githubusercontent.com"

DEFAULT_ORG = "konflux-ci"

# AI review tool config file paths to probe via raw.githubusercontent.com
AI_REVIEW_PROBES = {
    "coderabbit": [".coderabbit.yaml"],
    "qodo": [".pr_agent.toml"],
    "gemini": [".gemini/config.yaml", ".gemini/styleguide.md"],
}

# Workflow file patterns that indicate Qodo/PR-Agent usage (GitHub Actions)
QODO_WORKFLOW_PATTERNS = [
    "qodo-ai/pr-agent",
    "codiumai/pr-agent",
]

# Common Tekton filename suffixes to probe via raw.githubusercontent.com
# When API budget is exhausted, we try these patterns instead of listing dirs.
TEKTON_PROBE_SUFFIXES = [
    "-pull-request.yaml",
    "-push.yaml",
    "-pull-request.yml",
    "-push.yml",
]


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class RepoInfo:
    """Collected information about a single repository."""

    name: str
    full_name: str
    default_branch: str
    archived: bool
    fork: bool

    # AI review tools detected
    ai_tools: list[str] = field(default_factory=list)
    ai_tool_details: dict[str, list[str]] = field(default_factory=dict)

    # CI detection
    has_tekton: bool = False
    tekton_files: list[str] = field(default_factory=list)
    has_openshift_ci: bool = False
    openshift_ci_sources: list[str] = field(default_factory=list)
    has_junit_indicators: bool = False
    junit_details: list[str] = field(default_factory=list)

    @property
    def has_ai_review(self) -> bool:
        return len(self.ai_tools) > 0

    @property
    def has_ci(self) -> bool:
        return self.has_tekton or self.has_openshift_ci

    @property
    def has_ci_with_junit(self) -> bool:
        return self.has_ci


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


class RateLimitExhausted(Exception):
    """Raised when GitHub API rate limit is too low to continue."""

    pass


class GitHubClient:
    """Thin wrapper around urllib for GitHub API and raw content fetches."""

    def __init__(self, token: Optional[str] = None, min_remaining: int = 2):
        self.token = token
        self.min_remaining = min_remaining
        self._api_calls = 0
        self._raw_calls = 0
        self._rate_remaining: Optional[int] = None
        self._rate_reset: Optional[int] = None
        self._lock = Lock()

    def _make_request(
        self, url: str, accept: str = "application/vnd.github+json"
    ) -> tuple[int, Optional[bytes], dict]:
        """Make an HTTP GET request. Returns (status_code, body, headers)."""
        req = urllib.request.Request(url)
        req.add_header("Accept", accept)
        req.add_header("User-Agent", "konflux-ci-scanner/1.0")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                headers = {k.lower(): v for k, v in resp.getheaders()}
                return resp.status, resp.read(), headers
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in e.headers.items()}
            return e.code, None, headers
        except (TimeoutError, OSError, urllib.error.URLError) as e:
            log.debug("Request failed for %s: %s", url, e)
            return 0, None, {}

    def api_get(
        self, path: str, bypass_rate_check: bool = False
    ) -> tuple[int, Optional[dict | list], dict]:
        """GET from the GitHub API. Returns (status, parsed_json, headers).

        Raises RateLimitExhausted if remaining API calls are too low,
        unless bypass_rate_check is True.
        """
        if (
            not bypass_rate_check
            and self._rate_remaining is not None
            and self._rate_remaining <= self.min_remaining
        ):
            raise RateLimitExhausted(
                f"Only {self._rate_remaining} API calls remaining "
                f"(minimum: {self.min_remaining})"
            )

        url = f"{GITHUB_API}/{path.lstrip('/')}"
        with self._lock:
            self._api_calls += 1
        status, body, headers = self._make_request(url)

        # Track rate limit
        with self._lock:
            remaining = headers.get("x-ratelimit-remaining")
            if remaining is not None:
                self._rate_remaining = int(remaining)
            reset = headers.get("x-ratelimit-reset")
            if reset is not None:
                self._rate_reset = int(reset)

        if (
            not bypass_rate_check
            and status == 403
            and self._rate_remaining is not None
            and self._rate_remaining <= 0
        ):
            raise RateLimitExhausted("GitHub API rate limit exceeded (HTTP 403)")

        parsed = json.loads(body) if body else None
        self._log_rate_limit()
        return status, parsed, headers

    def raw_get(
        self, owner: str, repo: str, branch: str, path: str
    ) -> tuple[int, Optional[bytes]]:
        """GET from raw.githubusercontent.com. Does not consume API quota."""
        encoded_path = urllib.parse.quote(path, safe="/")
        url = f"{RAW_GH}/{owner}/{repo}/{branch}/{encoded_path}"
        with self._lock:
            self._raw_calls += 1
        status, body, _ = self._make_request(url, accept="*/*")
        return status, body

    def raw_exists(self, owner: str, repo: str, branch: str, path: str) -> bool:
        """Check if a file exists via raw.githubusercontent.com."""
        status, _ = self.raw_get(owner, repo, branch, path)
        return status == 200

    @property
    def api_budget_ok(self) -> bool:
        """Return True if we have enough API budget for more calls."""
        if self._rate_remaining is None:
            return True
        return self._rate_remaining > self.min_remaining

    def _log_rate_limit(self):
        """Log rate limit status when getting low."""
        if self._rate_remaining is not None and self._rate_remaining < 15:
            log.warning(
                "GitHub API rate limit: %d remaining (resets at epoch %s)",
                self._rate_remaining,
                self._rate_reset or "?",
            )

    @property
    def stats(self) -> dict:
        return {
            "api_calls": self._api_calls,
            "raw_calls": self._raw_calls,
            "rate_remaining": self._rate_remaining,
        }


# ---------------------------------------------------------------------------
# Scanning logic
# ---------------------------------------------------------------------------


def list_org_repos(client: GitHubClient, org: str) -> list[dict]:
    """List all public repos in the given GitHub org."""
    repos: list[dict] = []
    page = 1
    while True:
        status, data, _ = client.api_get(
            f"/orgs/{org}/repos?type=public&per_page=100&page={page}",
            bypass_rate_check=True,
        )
        if status != 200:
            log.error("Failed to list repos for %s (HTTP %d)", org, status)
            break
        if not data or not isinstance(data, list):
            break
        repos.extend(data)
        if len(data) < 100:
            break
        page += 1
        time.sleep(0.1)
    log.info("Found %d repos in %s", len(repos), org)
    return repos


def check_tekton_via_api(
    client: GitHubClient, owner: str, repo: str
) -> tuple[bool, list[str]]:
    """Check for .tekton/ directory via the GitHub Contents API.

    Returns (has_tekton, list_of_yaml_files).
    Uses 1 API call.
    """
    status, data, _ = client.api_get(f"/repos/{owner}/{repo}/contents/.tekton")
    if status != 200 or not isinstance(data, list):
        return False, []

    yaml_files = [
        e["name"]
        for e in data
        if e.get("type") == "file"
        and (e["name"].endswith(".yaml") or e["name"].endswith(".yml"))
    ]
    return len(yaml_files) > 0, [f".tekton/{f}" for f in yaml_files]


def check_tekton_via_raw(
    client: GitHubClient, owner: str, repo: str, branch: str
) -> tuple[bool, list[str]]:
    """Check for .tekton/ pipeline files using raw.githubusercontent.com.

    Tries common Konflux filename conventions. No API quota cost, but may
    miss repos with non-standard naming.
    """
    found_files = []
    for suffix in TEKTON_PROBE_SUFFIXES:
        path = f".tekton/{repo}{suffix}"
        if client.raw_exists(owner, repo, branch, path):
            found_files.append(path)

    return len(found_files) > 0, found_files


def check_workflows_for_qodo(
    client: GitHubClient, owner: str, repo: str, branch: str
) -> Optional[str]:
    """Check GitHub Actions workflows for Qodo/PR-Agent references.

    Lists the .github/workflows/ directory via Contents API, then reads
    each workflow file via raw.githubusercontent.com.

    Returns the workflow path if found, else None.
    """
    status, data, _ = client.api_get(
        f"/repos/{owner}/{repo}/contents/.github/workflows"
    )
    if status != 200 or not isinstance(data, list):
        return None

    workflow_files = [
        e["name"]
        for e in data
        if e.get("type") == "file"
        and (e["name"].endswith(".yml") or e["name"].endswith(".yaml"))
    ]

    for wf_name in workflow_files:
        wf_path = f".github/workflows/{wf_name}"
        status, content = client.raw_get(owner, repo, branch, wf_path)
        if status == 200 and content:
            text = content.decode("utf-8", errors="replace")
            for pattern in QODO_WORKFLOW_PATTERNS:
                if pattern in text:
                    return wf_path

    return None


def check_workflows_for_qodo_raw(
    client: GitHubClient, owner: str, repo: str, branch: str
) -> Optional[str]:
    """Check for Qodo in common workflow filenames via raw (no API cost).

    Tries common workflow filenames that repos might use for PR-Agent.
    """
    common_wf_names = [
        "pr_agent.yml",
        "pr_agent.yaml",
        "pr-agent.yml",
        "pr-agent.yaml",
    ]
    for wf_name in common_wf_names:
        wf_path = f".github/workflows/{wf_name}"
        status, content = client.raw_get(owner, repo, branch, wf_path)
        if status == 200 and content:
            text = content.decode("utf-8", errors="replace")
            for pattern in QODO_WORKFLOW_PATTERNS:
                if pattern in text:
                    return wf_path
    return None


def check_ai_review_tools(
    client: GitHubClient,
    owner: str,
    repo: str,
    branch: str,
    use_api_for_workflows: bool = False,
) -> tuple[list[str], dict[str, list[str]]]:
    """Detect AI PR review tools via config file checks and workflow scanning.

    All config file checks use raw.githubusercontent.com (no API cost).
    Workflow scanning optionally uses Contents API if budget allows.
    """
    tools_found: list[str] = []
    details: dict[str, list[str]] = {}

    # -- CodeRabbit --
    for path in AI_REVIEW_PROBES["coderabbit"]:
        if client.raw_exists(owner, repo, branch, path):
            if "coderabbit" not in tools_found:
                tools_found.append("coderabbit")
                details["coderabbit"] = []
            details["coderabbit"].append(f"config: {path}")

    # -- Qodo / PR-Agent --
    for path in AI_REVIEW_PROBES["qodo"]:
        if client.raw_exists(owner, repo, branch, path):
            if "qodo" not in tools_found:
                tools_found.append("qodo")
                details["qodo"] = []
            details["qodo"].append(f"config: {path}")

    # Check workflows for Qodo/PR-Agent action references
    if "qodo" not in tools_found:
        if use_api_for_workflows:
            wf = check_workflows_for_qodo(client, owner, repo, branch)
        else:
            wf = check_workflows_for_qodo_raw(client, owner, repo, branch)
        if wf:
            tools_found.append("qodo")
            details["qodo"] = [f"workflow: {wf}"]

    # -- Gemini Code Assist --
    for path in AI_REVIEW_PROBES["gemini"]:
        if client.raw_exists(owner, repo, branch, path):
            if "gemini" not in tools_found:
                tools_found.append("gemini")
                details["gemini"] = []
            details["gemini"].append(f"config: {path}")

    return tools_found, details


def check_openshift_ci_batch(
    client: GitHubClient, org: str, repos: list[str]
) -> dict[str, list[str]]:
    """Batch-check OpenShift CI by listing org-level directories.

    Lists each org-level directory in openshift/release once (3 API calls),
    then matches repo names locally.
    """
    result: dict[str, list[str]] = {}

    org_dirs = [
        f"ci-operator/config/{org}",
        f"ci-operator/jobs/{org}",
        f"core-services/prow/02_config/{org}",
    ]

    for org_dir in org_dirs:
        try:
            status, data, _ = client.api_get(
                f"/repos/openshift/release/contents/{org_dir}"
            )
        except RateLimitExhausted:
            log.warning("Rate limit exhausted during OpenShift CI check")
            break

        if status == 200 and isinstance(data, list):
            found_repos = {e["name"] for e in data if e["type"] == "dir"}
            for repo in repos:
                if repo in found_repos:
                    if repo not in result:
                        result[repo] = []
                    result[repo].append(f"{org_dir}/{repo}")
                    log.debug("OpenShift CI config: %s/%s", org_dir, repo)
        elif status == 404:
            log.debug("No OpenShift CI org dir: %s", org_dir)
        else:
            log.warning("Error checking %s (HTTP %d)", org_dir, status)
        time.sleep(0.1)

    return result


def check_org_level_ai_configs(client: GitHubClient, org: str) -> dict[str, bool]:
    """Check for org-level AI review tool configuration repos.

    Uses raw.githubusercontent.com only (no API cost).
    """
    org_configs: dict[str, bool] = {}

    # CodeRabbit: org-wide config repo
    if client.raw_exists(org, "coderabbit", "main", ".coderabbit.yaml"):
        org_configs["coderabbit_org_config"] = True
        log.info("Found org-level CodeRabbit config in %s/coderabbit", org)

    # Qodo: org-wide config repo
    if client.raw_exists(org, "pr-agent-settings", "main", ".pr_agent.toml"):
        org_configs["qodo_org_config"] = True
        log.info("Found org-level Qodo config in %s/pr-agent-settings", org)

    return org_configs


# ---------------------------------------------------------------------------
# Scanning pipeline
# ---------------------------------------------------------------------------


def scan_repo(
    client: GitHubClient,
    repo_data: dict,
    use_api: bool = True,
) -> RepoInfo:
    """Scan a single repository for AI review tools and CI/JUnit indicators."""
    name = repo_data["name"]
    owner = repo_data["owner"]["login"]
    branch = repo_data["default_branch"]

    info = RepoInfo(
        name=name,
        full_name=repo_data["full_name"],
        default_branch=branch,
        archived=repo_data.get("archived", False),
        fork=repo_data.get("fork", False),
    )

    if info.archived:
        log.debug("Skipping archived repo: %s", name)
        return info

    # Check AI review tools (primarily uses raw, no API cost)
    info.ai_tools, info.ai_tool_details = check_ai_review_tools(
        client, owner, name, branch, use_api_for_workflows=use_api
    )

    # Check Tekton/Konflux CI
    if use_api and client.api_budget_ok:
        try:
            info.has_tekton, info.tekton_files = check_tekton_via_api(
                client, owner, name
            )
        except RateLimitExhausted:
            log.warning("Rate limit hit; falling back to raw probes for %s", name)
            info.has_tekton, info.tekton_files = check_tekton_via_raw(
                client, owner, name, branch
            )
    else:
        info.has_tekton, info.tekton_files = check_tekton_via_raw(
            client, owner, name, branch
        )

    if info.has_tekton:
        info.has_junit_indicators = True
        info.junit_details.append(
            "Konflux build pipelines include scanning tasks that produce "
            "TEST_OUTPUT results and attach SARIF/scan results to OCI images "
            "via oras attach"
        )

    return info


def scan_org(client: GitHubClient, org: str) -> list[RepoInfo]:
    """Scan all repos in a GitHub org."""
    log.info("Listing repos for org: %s", org)
    raw_repos = list_org_repos(client, org)

    # Sort by name for consistent output
    raw_repos.sort(key=lambda r: r["name"])

    active_repos = [r for r in raw_repos if not r.get("archived", False)]
    repo_names = [r["name"] for r in active_repos]

    # Check org-level AI configs (raw only, no API cost)
    log.info("Checking org-level AI review tool configs...")
    org_ai_configs = check_org_level_ai_configs(client, org)

    # Check OpenShift CI in batch (3 API calls for org-level dirs)
    log.info("Checking OpenShift CI configs in openshift/release...")
    try:
        openshift_ci = check_openshift_ci_batch(client, org, repo_names)
    except RateLimitExhausted:
        log.warning("Rate limit exhausted during OpenShift CI check; skipping")
        openshift_ci = {}

    # Decide whether to use API for per-repo checks based on budget
    # Per-repo API usage: 1 call for .tekton/ dir, optionally 1 for workflows
    # With N repos, we need roughly N API calls.
    use_api = client.api_budget_ok
    if not use_api:
        log.warning(
            "API budget low (%s remaining); using raw probes for Tekton detection. "
            "Results may be incomplete for repos with non-standard Tekton filenames. "
            "Re-run with --github-token for complete results.",
            client.stats["rate_remaining"],
        )

    # Scan repos concurrently (raw requests are the bottleneck)
    results_map: dict[str, RepoInfo] = {}
    total = len(raw_repos)
    completed = 0
    completed_lock = Lock()

    def _scan_one(repo_data: dict) -> tuple[str, RepoInfo]:
        nonlocal completed
        name = repo_data["name"]
        current_use_api = use_api and client.api_budget_ok
        info = scan_repo(client, repo_data, use_api=current_use_api)
        with completed_lock:
            completed += 1
            log.info("[%d/%d] Scanned %s", completed, total, name)
        return name, info

    max_workers = 10  # Parallel HTTP requests
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan_one, rd): rd["name"] for rd in raw_repos}
        for future in as_completed(futures):
            name, info = future.result()

            # Merge OpenShift CI data
            if name in openshift_ci:
                info.has_openshift_ci = True
                info.openshift_ci_sources = openshift_ci[name]
                if not info.has_junit_indicators:
                    info.has_junit_indicators = True
                    info.junit_details.append(
                        "OpenShift CI (ci-operator) inherently produces "
                        "junit_operator.xml and collects junit*.xml artifacts"
                    )

            results_map[name] = info

    # Sort results by repo name for consistent output
    results = [results_map[rd["name"]] for rd in raw_repos if rd["name"] in results_map]

    log.info(
        "Scan complete. API calls: %d, Raw calls: %d, Rate remaining: %s",
        client.stats["api_calls"],
        client.stats["raw_calls"],
        client.stats["rate_remaining"],
    )
    return results


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def format_text(results: list[RepoInfo], org_ai_configs: dict) -> str:
    """Format results as human-readable text."""
    lines = []
    lines.append("=" * 80)
    lines.append("Konflux-CI Org Repository Scanner Results")
    lines.append("=" * 80)
    lines.append("")

    # Summary
    repos_with_ai = [r for r in results if r.has_ai_review and not r.archived]
    repos_with_ci = [r for r in results if r.has_ci and not r.archived]
    repos_with_both = [
        r for r in results if r.has_ai_review and r.has_ci and not r.archived
    ]
    active_repos = [r for r in results if not r.archived]

    lines.append("SUMMARY")
    lines.append(f"  Total repos:           {len(results)}")
    lines.append(f"  Active (non-archived): {len(active_repos)}")
    lines.append(f"  With AI review tools:  {len(repos_with_ai)}")
    lines.append(f"  With CI (JUnit):       {len(repos_with_ci)}")
    lines.append(f"  With BOTH:             {len(repos_with_both)}")
    lines.append("")

    if org_ai_configs:
        lines.append("ORG-LEVEL AI CONFIGS")
        for k, v in org_ai_configs.items():
            lines.append(f"  {k}: {v}")
        lines.append("")

    # Repos with AI review tools
    lines.append("-" * 80)
    lines.append("REPOS WITH AI PR REVIEW TOOLS")
    lines.append("-" * 80)
    if repos_with_ai:
        for r in repos_with_ai:
            lines.append(f"\n  {r.full_name}")
            for tool in r.ai_tools:
                detail_str = ", ".join(r.ai_tool_details.get(tool, []))
                lines.append(f"    - {tool}: {detail_str}")
    else:
        lines.append("  (none detected via config files)")
        lines.append("  Note: tools installed as GitHub Apps with default settings")
        lines.append("  are not detectable without admin API access.")
    lines.append("")

    # Repos with CI / JUnit
    lines.append("-" * 80)
    lines.append("REPOS WITH CI ENABLED (JUnit/Test Results Available)")
    lines.append("-" * 80)
    if repos_with_ci:
        for r in repos_with_ci:
            ci_types = []
            if r.has_tekton:
                ci_types.append("Konflux/Tekton")
            if r.has_openshift_ci:
                ci_types.append("OpenShift CI")
            lines.append(f"\n  {r.full_name}  [{', '.join(ci_types)}]")
            if r.has_tekton:
                lines.append(f"    Tekton pipelines: {len(r.tekton_files)} file(s)")
                for f in r.tekton_files[:5]:
                    lines.append(f"      - {f}")
                if len(r.tekton_files) > 5:
                    lines.append(f"      ... and {len(r.tekton_files) - 5} more")
            if r.has_openshift_ci:
                for src in r.openshift_ci_sources:
                    lines.append(f"    OpenShift CI: {src}")
            for detail in r.junit_details:
                lines.append(f"    JUnit: {detail}")
    else:
        lines.append("  (none detected)")
    lines.append("")

    # Repos with BOTH
    lines.append("-" * 80)
    lines.append("REPOS WITH BOTH AI REVIEW AND CI (the target list)")
    lines.append("-" * 80)
    if repos_with_both:
        for r in repos_with_both:
            ci_types = []
            if r.has_tekton:
                ci_types.append("Konflux/Tekton")
            if r.has_openshift_ci:
                ci_types.append("OpenShift CI")
            tools_str = ", ".join(r.ai_tools)
            lines.append(
                f"  {r.full_name}  [AI: {tools_str}] [CI: {', '.join(ci_types)}]"
            )
    else:
        lines.append("  (none detected)")
    lines.append("")

    # Caveats
    lines.append("-" * 80)
    lines.append("CAVEATS")
    lines.append("-" * 80)
    lines.append(
        "  - AI tools installed as GitHub Apps with default settings (no config"
    )
    lines.append("    file) are NOT detectable without admin API access or PR comment")
    lines.append("    inspection.")
    lines.append(
        "  - Tekton detection without API access uses filename probing and may"
    )
    lines.append("    miss repos with non-standard .tekton/ file naming.")
    lines.append("  - OpenShift CI detection checks the openshift/release repo for")
    lines.append("    centralized config; repos using only in-repo Prow config may be")
    lines.append("    missed.")
    lines.append("")

    return "\n".join(lines)


def format_json(results: list[RepoInfo]) -> str:
    """Format results as JSON."""
    output = []
    for r in results:
        if r.archived:
            continue
        output.append(
            {
                "name": r.name,
                "full_name": r.full_name,
                "default_branch": r.default_branch,
                "archived": r.archived,
                "fork": r.fork,
                "ai_review": {
                    "enabled": r.has_ai_review,
                    "tools": r.ai_tools,
                    "details": r.ai_tool_details,
                },
                "ci": {
                    "enabled": r.has_ci,
                    "tekton": r.has_tekton,
                    "tekton_files": r.tekton_files,
                    "openshift_ci": r.has_openshift_ci,
                    "openshift_ci_sources": r.openshift_ci_sources,
                    "junit_available": r.has_ci_with_junit,
                    "junit_details": r.junit_details,
                },
            }
        )
    return json.dumps(output, indent=2)


def format_csv(results: list[RepoInfo]) -> str:
    """Format results as CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "repo",
            "has_ai_review",
            "ai_tools",
            "has_ci",
            "ci_types",
            "has_tekton",
            "has_openshift_ci",
            "has_both",
        ]
    )
    for r in results:
        if r.archived:
            continue
        ci_types = []
        if r.has_tekton:
            ci_types.append("konflux")
        if r.has_openshift_ci:
            ci_types.append("openshift-ci")
        writer.writerow(
            [
                r.full_name,
                r.has_ai_review,
                ";".join(r.ai_tools),
                r.has_ci,
                ";".join(ci_types),
                r.has_tekton,
                r.has_openshift_ci,
                r.has_ai_review and r.has_ci,
            ]
        )
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Scan the konflux-ci GitHub org for AI review tools and CI/JUnit presence."
        ),
    )
    parser.add_argument(
        "--github-token",
        default=os.environ.get("GITHUB_TOKEN"),
        help=(
            "GitHub personal access token (default: $GITHUB_TOKEN env var). "
            "Optional; unauthenticated access has a 60 req/hr rate limit."
        ),
    )
    parser.add_argument(
        "--org",
        default=DEFAULT_ORG,
        help=f"GitHub org to scan (default: {DEFAULT_ORG})",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    client = GitHubClient(token=args.github_token)

    # Run the scan
    results = scan_org(client, args.org)

    # Format output
    org_ai_configs: dict = {}
    if args.format == "json":
        output = format_json(results)
    elif args.format == "csv":
        output = format_csv(results)
    else:
        output = format_text(results, org_ai_configs)

    # Write output
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        log.info("Results written to %s", args.output)
    else:
        print(output)


if __name__ == "__main__":
    main()
