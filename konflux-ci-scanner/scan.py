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

# Bot usernames that comment on PRs for each AI review tool.
# Used with the GitHub Search API (requires authentication).
AI_REVIEW_BOTS = {
    "coderabbit": ["coderabbitai[bot]"],
    "qodo": ["qodo-code-review[bot]"],
    "gemini": ["gemini-code-assist[bot]"],
}

# Bot usernames whose PR comments indicate CI test results are exposed.
# Used with the GitHub Search API (requires authentication).
# "konflux-ci-qe-bot" posts test scenario results with oras pull instructions.
# "openshift-ci[bot]" indicates OpenShift CI (Prow) is managing the repo.
# "codecov[bot]" and "codecov-commenter" indicate code coverage from test runs.
CI_RESULTS_BOTS = {
    "konflux_qe": ["konflux-ci-qe-bot"],
    "openshift_ci": ["openshift-ci[bot]"],
    "codecov": ["codecov[bot]", "codecov-commenter"],
}

# Workflow file patterns that indicate Qodo/PR-Agent usage (GitHub Actions)
QODO_WORKFLOW_PATTERNS = [
    "qodo-ai/pr-agent",
    "codiumai/pr-agent",
]

# Tekton filename patterns to probe via raw.githubusercontent.com
# When API budget is exhausted, we try these patterns instead of listing dirs.
# Pattern types:
#   "{repo}" is replaced with the repo name
#   Literal strings are tried as-is
TEKTON_PROBE_PATTERNS = [
    # Standard Konflux naming: {reponame}-{event}.yaml
    ".tekton/{repo}-pull-request.yaml",
    ".tekton/{repo}-push.yaml",
    # Bare naming (no repo prefix)
    ".tekton/pull-request.yaml",
    ".tekton/push.yaml",
    # Common extra pipeline files
    ".tekton/build-pipeline.yaml",
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

    # Test result exposure (beyond default Konflux build scans)
    has_exposed_results: bool = False
    exposed_results_evidence: list[str] = field(default_factory=list)

    # Evidence URLs for linking in reports.
    # Keys: "ai:<tool>", "tekton", "openshift_ci", "results:<category>"
    evidence_urls: dict[str, str] = field(default_factory=dict)

    @property
    def has_ai_review(self) -> bool:
        return len(self.ai_tools) > 0

    @property
    def has_ci(self) -> bool:
        return self.has_tekton or self.has_openshift_ci

    @property
    def ci_level(self) -> str:
        """Categorize the CI level.

        Returns one of:
          - "none"
          - "konflux" (build pipeline only)
          - "konflux+results" (build pipeline + exposed test results)
          - "openshift-ci" (OpenShift CI only)
          - "konflux+openshift-ci" (both, inherently has results)
        """
        if not self.has_ci:
            return "none"
        parts = []
        if self.has_tekton:
            parts.append("konflux")
        if self.has_openshift_ci:
            parts.append("openshift-ci")
        if self.has_exposed_results and "openshift-ci" not in parts:
            # OpenShift CI inherently exposes junit, so only annotate
            # konfux repos that also have evidence of exposed results
            parts = ["konflux+results" if p == "konflux" else p for p in parts]
        return "+".join(parts)


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
    miss repos with unusual naming (e.g., hash suffixes, component names
    that differ significantly from the repo name).
    """
    found_files = []
    for pattern in TEKTON_PROBE_PATTERNS:
        path = pattern.format(repo=repo)
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


def search_pr_comments_for_bots(
    client: GitHubClient, org: str
) -> dict[str, dict[str, tuple[int, str]]]:
    """Search for AI review bot comments on PRs across the org.

    Uses the GitHub Search API to find PRs where known AI review bots
    have commented. This detects tools installed as GitHub Apps even
    when no config file is present in the repo.

    Requires authentication (search API is auth-only for some queries).
    Uses the search rate limit (30 req/min), separate from core rate limit.

    Returns:
        dict mapping repo name -> {tool_name: (pr_count, example_pr_url)}
    """
    if not client.token:
        log.info(
            "Skipping PR comment search (requires --github-token). "
            "Only config-file-based detection will be used."
        )
        return {}

    result: dict[str, dict[str, tuple[int, str]]] = {}

    for tool, bot_names in AI_REVIEW_BOTS.items():
        for bot in bot_names:
            log.info("Searching for %s bot (%s) activity...", tool, bot)
            page = 1
            while True:
                query = f"org:{org} is:pr commenter:{bot}"
                encoded = urllib.parse.quote(query, safe=":")
                try:
                    status, data, _ = client.api_get(
                        f"/search/issues?q={encoded}"
                        f"&per_page=100&page={page}&sort=updated"
                    )
                except RateLimitExhausted:
                    log.warning(
                        "Rate limit hit during PR comment search for %s",
                        tool,
                    )
                    break

                if status == 422:
                    log.debug("Search API rejected bot name %s (HTTP 422)", bot)
                    break
                if status != 200 or not isinstance(data, dict):
                    log.warning("Search failed for %s (HTTP %d)", bot, status)
                    break

                items = data.get("items", [])
                if not items:
                    break

                for item in items:
                    repo_url = item.get("repository_url", "")
                    repo_name = repo_url.rstrip("/").rsplit("/", 1)[-1]
                    pr_url = item.get("html_url", "")
                    if repo_name:
                        if repo_name not in result:
                            result[repo_name] = {}
                        prev = result[repo_name].get(tool)
                        count = (prev[0] if prev else 0) + 1
                        # Keep the first (most recent) example URL
                        example = prev[1] if prev else pr_url
                        result[repo_name][tool] = (count, example)

                if len(items) < 100:
                    break
                page += 1
                time.sleep(2.1)

    return result


def search_ci_results_bots(
    client: GitHubClient, org: str
) -> dict[str, dict[str, tuple[int, str]]]:
    """Search for CI test-result bot comments on PRs across the org.

    Looks for bots that post test result summaries, coverage reports,
    or oras pull instructions on PRs. This is evidence that CI test
    results are being exposed and accessible.

    Returns:
        dict mapping repo name -> {bot_category: (pr_count, example_pr_url)}
    """
    if not client.token:
        log.info("Skipping CI results bot search (requires --github-token).")
        return {}

    result: dict[str, dict[str, tuple[int, str]]] = {}

    for category, bot_names in CI_RESULTS_BOTS.items():
        for bot in bot_names:
            log.info(
                "Searching for CI results bot %s (%s) activity...",
                category,
                bot,
            )
            page = 1
            while True:
                query = f"org:{org} is:pr commenter:{bot}"
                encoded = urllib.parse.quote(query, safe=":")
                try:
                    status, data, _ = client.api_get(
                        f"/search/issues?q={encoded}"
                        f"&per_page=100&page={page}&sort=updated"
                    )
                except RateLimitExhausted:
                    log.warning("Rate limit hit during CI bot search for %s", bot)
                    break

                if status == 422:
                    log.debug("Search API rejected bot name %s (HTTP 422)", bot)
                    break
                if status != 200 or not isinstance(data, dict):
                    log.warning("Search failed for %s (HTTP %d)", bot, status)
                    break

                items = data.get("items", [])
                if not items:
                    break

                for item in items:
                    repo_url = item.get("repository_url", "")
                    repo_name = repo_url.rstrip("/").rsplit("/", 1)[-1]
                    pr_url = item.get("html_url", "")
                    if repo_name:
                        if repo_name not in result:
                            result[repo_name] = {}
                        prev = result[repo_name].get(category)
                        count = (prev[0] if prev else 0) + 1
                        example = prev[1] if prev else pr_url
                        result[repo_name][category] = (count, example)

                if len(items) < 100:
                    break
                page += 1
                time.sleep(2.1)

    return result


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
    try:
        info.ai_tools, info.ai_tool_details = check_ai_review_tools(
            client, owner, name, branch, use_api_for_workflows=use_api
        )
    except RateLimitExhausted:
        log.debug("Rate limit hit during AI check for %s; retrying raw-only", name)
        info.ai_tools, info.ai_tool_details = check_ai_review_tools(
            client, owner, name, branch, use_api_for_workflows=False
        )

    # Build evidence URLs for AI config files found
    for tool, dets in info.ai_tool_details.items():
        for d in dets:
            if d.startswith("config: "):
                path = d[len("config: ") :]
                url = f"https://github.com/{owner}/{name}/blob/{branch}/{path}"
                info.evidence_urls.setdefault(f"ai:{tool}", url)

    # Check Tekton/Konflux CI
    if use_api and client.api_budget_ok:
        try:
            info.has_tekton, info.tekton_files = check_tekton_via_api(
                client, owner, name
            )
        except RateLimitExhausted:
            log.debug("Rate limit hit; falling back to raw probes for %s", name)
            info.has_tekton, info.tekton_files = check_tekton_via_raw(
                client, owner, name, branch
            )
    else:
        info.has_tekton, info.tekton_files = check_tekton_via_raw(
            client, owner, name, branch
        )

    # Evidence URL for Tekton: link to .tekton/ directory
    if info.has_tekton:
        info.evidence_urls["tekton"] = (
            f"https://github.com/{owner}/{name}/tree/{branch}/.tekton"
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

    # Search for AI review bot activity on PRs (uses search API, needs auth)
    log.info("Searching for AI review bot activity on PRs...")
    pr_bot_activity = search_pr_comments_for_bots(client, org)

    # Search for CI test-result bot activity (uses search API, needs auth)
    log.info("Searching for CI test-result bot activity on PRs...")
    ci_bot_activity = search_ci_results_bots(client, org)

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
                # OpenShift CI inherently exposes junit results
                info.has_exposed_results = True
                info.exposed_results_evidence.append(
                    "openshift_ci: ci-operator inherently produces "
                    "junit_operator.xml and collects junit*.xml artifacts"
                )
                # Link to the first config dir in openshift/release
                first_src = openshift_ci[name][0]
                info.evidence_urls.setdefault(
                    "openshift_ci",
                    f"https://github.com/openshift/release/tree/master/{first_src}",
                )

            # Merge PR bot activity data (AI review)
            if name in pr_bot_activity:
                for tool, (pr_count, example_url) in pr_bot_activity[name].items():
                    if tool not in info.ai_tools:
                        info.ai_tools.append(tool)
                        info.ai_tool_details[tool] = []
                    detail = f"pr_comments: {pr_count} PRs with bot activity"
                    if detail not in info.ai_tool_details.get(tool, []):
                        info.ai_tool_details.setdefault(tool, []).append(detail)
                    # Store example PR URL as evidence
                    info.evidence_urls.setdefault(f"ai:{tool}", example_url)

            # Merge CI results bot activity
            if name in ci_bot_activity:
                for category, (pr_count, example_url) in ci_bot_activity[name].items():
                    if category == "openshift_ci":
                        info.has_openshift_ci = True
                        info.has_exposed_results = True
                        info.exposed_results_evidence.append(
                            f"openshift-ci[bot]: {pr_count} PRs with bot activity"
                        )
                        info.evidence_urls.setdefault(
                            "results:openshift_ci", example_url
                        )
                    elif category == "konflux_qe":
                        info.has_exposed_results = True
                        info.exposed_results_evidence.append(
                            f"konflux-ci-qe-bot: {pr_count} PRs with "
                            f"test result summaries and oras pull instructions"
                        )
                        info.evidence_urls.setdefault("results:konflux_qe", example_url)
                    elif category == "codecov":
                        info.has_exposed_results = True
                        info.exposed_results_evidence.append(
                            f"codecov: {pr_count} PRs with coverage reports"
                        )
                        info.evidence_urls.setdefault("results:codecov", example_url)

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

    # Repos with CI
    lines.append("-" * 80)
    lines.append("REPOS WITH CI ENABLED")
    lines.append("-" * 80)
    if repos_with_ci:
        for r in repos_with_ci:
            lines.append(f"\n  {r.full_name}  [{r.ci_level}]")
            if r.has_tekton:
                lines.append(f"    Tekton pipelines: {len(r.tekton_files)} file(s)")
                for f in r.tekton_files[:5]:
                    lines.append(f"      - {f}")
                if len(r.tekton_files) > 5:
                    lines.append(f"      ... and {len(r.tekton_files) - 5} more")
            if r.has_openshift_ci:
                for src in r.openshift_ci_sources:
                    lines.append(f"    OpenShift CI: {src}")
            if r.has_exposed_results:
                for ev in r.exposed_results_evidence:
                    lines.append(f"    Results: {ev}")
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
    lines.append("  - With --github-token: AI tools are detected via both config files")
    lines.append(
        "    AND PR comment history (search API). Without a token, only config"
    )
    lines.append("    file detection is available.")
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
                    "ci_level": r.ci_level,
                    "tekton": r.has_tekton,
                    "tekton_files": r.tekton_files,
                    "openshift_ci": r.has_openshift_ci,
                    "openshift_ci_sources": r.openshift_ci_sources,
                    "exposed_results": r.has_exposed_results,
                    "exposed_results_evidence": r.exposed_results_evidence,
                },
                "evidence_urls": r.evidence_urls,
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
            "ci_level",
            "has_tekton",
            "has_openshift_ci",
            "has_exposed_results",
            "has_both",
        ]
    )
    for r in results:
        if r.archived:
            continue
        writer.writerow(
            [
                r.full_name,
                r.has_ai_review,
                ";".join(r.ai_tools),
                r.has_ci,
                r.ci_level,
                r.has_tekton,
                r.has_openshift_ci,
                r.has_exposed_results,
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
