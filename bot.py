#!/usr/bin/env python3
"""CVE Bot — automatically analyze and fix Go CVEs from Jira tickets.

Monitors OCPBUGS for new CVE tickets assigned to a specific component,
analyzes each repo for impact, applies dependency fixes, and creates PRs.

Environment variables:
    JIRA_URL          - Jira instance URL (e.g. https://redhat.atlassian.net)
    JIRA_USERNAME     - Jira email
    JIRA_API_TOKEN    - Jira API token
    GITHUB_TOKEN      - GitHub token for creating PRs
    TEAM_COMPONENTS   - Comma-separated Jira components to watch
                        (e.g. "networking-ingress-commatrix,ptp")
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("cve-bot")

JIRA_URL = os.environ.get("JIRA_URL", "https://redhat.atlassian.net").rstrip("/")
JIRA_USER = os.environ.get("JIRA_USERNAME", "")
JIRA_TOKEN = os.environ.get("JIRA_API_TOKEN", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
TEAM_COMPONENTS = [
    c.strip()
    for c in os.environ.get("TEAM_COMPONENTS", "").split(",")
    if c.strip()
]
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

OCP_BUILD_DATA_REPO = "https://github.com/openshift-eng/ocp-build-data.git"

RESULTS_DIR = Path(os.environ.get("RESULTS_DIR", "/tmp/cve-bot-results"))


@dataclass
class CVETicket:
    key: str
    cve_id: str
    summary: str
    component: str
    version: str
    status: str


@dataclass
class AnalysisResult:
    ticket: CVETicket
    repo_url: str = ""
    branch: str = ""
    package: str = ""
    current_version: str = ""
    fixed_version: str = ""
    risk_level: str = "UNKNOWN"
    fix_type: str = "UNKNOWN"
    govulncheck_output: str = ""
    pr_url: str = ""
    error: str = ""


# ---------------------------------------------------------------------------
# Jira helpers
# ---------------------------------------------------------------------------

def _jira_get(path: str) -> dict:
    resp = requests.get(
        f"{JIRA_URL}/rest/api/3/{path}",
        auth=(JIRA_USER, JIRA_TOKEN),
        headers={"Accept": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def _jira_search(jql: str, max_results: int = 50) -> list[dict]:
    resp = requests.post(
        f"{JIRA_URL}/rest/api/3/search/jql",
        json={"jql": jql, "fields": ["summary", "components", "labels", "status"], "maxResults": max_results},
        auth=(JIRA_USER, JIRA_TOKEN),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("issues", [])


def _jira_add_comment(issue_key: str, body: str) -> None:
    if DRY_RUN:
        log.info("[DRY RUN] Would comment on %s: %s", issue_key, body[:100])
        return
    requests.post(
        f"{JIRA_URL}/rest/api/3/issue/{issue_key}/comment",
        json={
            "body": {
                "type": "doc",
                "version": 1,
                "content": [{"type": "paragraph", "content": [{"type": "text", "text": body}]}],
            }
        },
        auth=(JIRA_USER, JIRA_TOKEN),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=30,
    )


def fetch_new_cve_tickets() -> list[CVETicket]:
    if not TEAM_COMPONENTS:
        log.error("TEAM_COMPONENTS not set")
        return []

    components_jql = ", ".join(f'"{c}"' for c in TEAM_COMPONENTS)
    jql = (
        f"project = OCPBUGS "
        f"AND issuetype = Vulnerability "
        f"AND labels = SecurityTracking "
        f"AND resolution = Unresolved "
        f"AND component in ({components_jql}) "
        f"AND labels not in (cve-bot-processed) "
        f"ORDER BY created DESC"
    )
    log.info("Searching Jira: %s", jql)
    raw_issues = _jira_search(jql)
    log.info("Found %d tickets", len(raw_issues))

    tickets = []
    for raw in raw_issues:
        fields = raw.get("fields", {})
        summary = fields.get("summary", "")

        cve_match = re.search(r"(CVE-\d{4}-\d+)", summary)
        version_match = re.search(r"\[(openshift-[\w.]+)\]", summary)
        components = [c.get("name", "") for c in (fields.get("components") or [])]

        if cve_match:
            tickets.append(CVETicket(
                key=raw["key"],
                cve_id=cve_match.group(1),
                summary=summary,
                component=components[0] if components else "",
                version=version_match.group(1) if version_match else "",
                status=(fields.get("status") or {}).get("name", "Unknown"),
            ))
    return tickets


# ---------------------------------------------------------------------------
# Repository mapping (via ocp-build-data)
# ---------------------------------------------------------------------------

def _run(cmd: list[str], cwd: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    log.debug("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=check, timeout=300)


def map_component_to_repo(component: str, version: str) -> tuple[str, str]:
    """Map a Jira component to a GitHub repo URL and branch using ocp-build-data."""
    tmpdir = tempfile.mkdtemp(prefix="ocp-build-data-")
    try:
        branch = version.replace("openshift-", "openshift-") if version else "openshift-4.17"
        _run(["git", "clone", "--depth=1", "--branch", branch, OCP_BUILD_DATA_REPO, tmpdir])

        mapping_file = Path(tmpdir) / "delivery_component_mapping.yml"
        if mapping_file.exists():
            content = mapping_file.read_text()
            pattern = re.compile(rf"{re.escape(component)}:.*?image_file:\s*(\S+)", re.DOTALL)
            match = pattern.search(content)
            if match:
                image_file = Path(tmpdir) / match.group(1)
                if image_file.exists():
                    image_content = image_file.read_text()
                    repo_match = re.search(r"web:\s*(https://github\.com/\S+)", image_content)
                    if repo_match:
                        repo_url = repo_match.group(1).rstrip("/")
                        ocp_version = version.replace("openshift-", "")
                        return repo_url, f"release-{ocp_version}"

        images_dir = Path(tmpdir) / "images"
        if images_dir.exists():
            for yml in images_dir.glob("*.yml"):
                content = yml.read_text()
                if component.lower() in content.lower():
                    repo_match = re.search(r"web:\s*(https://github\.com/\S+)", content)
                    if repo_match:
                        repo_url = repo_match.group(1).rstrip("/")
                        ocp_version = version.replace("openshift-", "")
                        return repo_url, f"release-{ocp_version}"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return "", ""


# ---------------------------------------------------------------------------
# CVE analysis
# ---------------------------------------------------------------------------

def _extract_cve_package(cve_id: str, summary: str) -> str:
    """Try to extract the affected Go package from the CVE summary."""
    known_patterns = {
        "grpc": "google.golang.org/grpc",
        "go-jose": "github.com/go-jose/go-jose",
        "golang.org/x/crypto": "golang.org/x/crypto",
        "golang.org/x/net": "golang.org/x/net",
        "golang.org/x/text": "golang.org/x/text",
        "net/http": "net/http",
        "crypto/tls": "crypto/tls",
        "buildkit": "github.com/moby/buildkit",
        "containerd": "github.com/containerd/containerd",
        "runc": "github.com/opencontainers/runc",
        "etcd": "go.etcd.io/etcd",
        "prometheus": "github.com/prometheus/prometheus",
    }
    summary_lower = summary.lower()
    for keyword, package in known_patterns.items():
        if keyword.lower() in summary_lower:
            return package
    return ""


def analyze_repo(repo_dir: str, cve_id: str, package: str) -> tuple[str, str, str, str]:
    """Run govulncheck and check if the repo is affected.

    Returns (risk_level, current_version, govulncheck_output, fix_type).
    """
    gomod = Path(repo_dir) / "go.mod"
    if not gomod.exists():
        return "NOT_GO_PROJECT", "", "", ""

    gomod_content = gomod.read_text()
    if package and package not in gomod_content:
        return "NOT_AFFECTED", "", "Package not found in go.mod", ""

    version_match = re.search(rf"{re.escape(package)}\s+(v[\d.]+\S*)", gomod_content)
    current_version = version_match.group(1) if version_match else "unknown"

    _run(["go", "install", "golang.org/x/vuln/cmd/govulncheck@latest"], cwd=repo_dir, check=False)

    result = _run(["govulncheck", "./..."], cwd=repo_dir, check=False)
    output = result.stdout + result.stderr

    if "Symbol Results" in output or "symbol" in output.lower():
        risk = "HIGH"
    elif "Package Results" in output or "package" in output.lower():
        risk = "LOW"
    elif cve_id.lower() in output.lower():
        risk = "LOW"
    else:
        risk = "NOT_AFFECTED"

    if "/" not in package:
        fix_type = "STDLIB"
    elif package.startswith("golang.org/x/"):
        fix_type = "EXTENDED_STDLIB"
    else:
        fix_type = "THIRD_PARTY"

    return risk, current_version, output[:2000], fix_type


def apply_fix(repo_dir: str, package: str, fixed_version: str) -> bool:
    """Bump the dependency and run go mod tidy. Returns True on success."""
    target = f"{package}@{fixed_version}" if not fixed_version.startswith("v") else f"{package}@{fixed_version}"

    result = _run(["go", "get", target], cwd=repo_dir, check=False)
    if result.returncode != 0:
        log.error("go get failed: %s", result.stderr)
        return False

    result = _run(["go", "mod", "tidy"], cwd=repo_dir, check=False)
    if result.returncode != 0:
        log.error("go mod tidy failed: %s", result.stderr)
        return False

    vendor_dir = Path(repo_dir) / "vendor"
    if vendor_dir.exists():
        result = _run(["go", "mod", "vendor"], cwd=repo_dir, check=False)
        if result.returncode != 0:
            log.error("go mod vendor failed: %s", result.stderr)
            return False

    return True


def run_tests(repo_dir: str) -> tuple[bool, str]:
    """Run go test. Returns (passed, output)."""
    result = _run(["go", "test", "./..."], cwd=repo_dir, check=False)
    output = result.stdout + result.stderr
    return result.returncode == 0, output[:2000]


def create_pr(repo_dir: str, ticket: CVETicket, package: str,
              old_version: str, fixed_version: str, risk: str) -> str:
    """Create a branch, commit, push, and open a PR. Returns the PR URL."""
    branch_name = f"fix-{ticket.cve_id.lower()}-{ticket.version}"

    _run(["git", "checkout", "-b", branch_name], cwd=repo_dir)

    is_upstream = False
    log_result = _run(["git", "log", "--oneline", "-10"], cwd=repo_dir, check=False)
    if "UPSTREAM:" in log_result.stdout:
        is_upstream = True

    _run(["git", "add", "-A"], cwd=repo_dir)

    if is_upstream:
        msg = f"UPSTREAM: <carry>: Bump {package} to {fixed_version} for {ticket.cve_id}"
    else:
        msg = f"{ticket.key}: Bump {package} to {fixed_version} for {ticket.cve_id}"

    _run(["git", "commit", "-m", msg], cwd=repo_dir)

    if DRY_RUN:
        log.info("[DRY RUN] Would push branch %s and create PR", branch_name)
        return f"[DRY RUN] PR would be created on branch {branch_name}"

    _run(["git", "push", "origin", branch_name], cwd=repo_dir)

    pr_body = f"""## CVE Fix

**CVE:** {ticket.cve_id}
**Jira:** [{ticket.key}]({JIRA_URL}/browse/{ticket.key})
**Package:** {package}
**Previous version:** {old_version} (vulnerable)
**Fixed version:** {fixed_version}
**Risk level:** {risk}

## Changes

- Updated `{package}` from `{old_version}` to `{fixed_version}` in `go.mod`
- Ran `go mod tidy`

## References

- https://www.cve.org/CVERecord?id={ticket.cve_id}
"""

    result = _run(
        ["gh", "pr", "create",
         "--title", msg,
         "--body", pr_body],
        cwd=repo_dir,
        check=False,
    )
    if result.returncode == 0:
        pr_url = result.stdout.strip()
        log.info("PR created: %s", pr_url)
        return pr_url
    else:
        log.error("Failed to create PR: %s", result.stderr)
        return ""


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def process_ticket(ticket: CVETicket) -> AnalysisResult:
    """Full pipeline: analyze → fix → PR for a single ticket."""
    result = AnalysisResult(ticket=ticket)
    log.info("Processing %s: %s", ticket.key, ticket.cve_id)

    # Map component to repo
    repo_url, branch = map_component_to_repo(ticket.component, ticket.version)
    if not repo_url:
        result.error = f"Could not map component '{ticket.component}' to a GitHub repo"
        log.warning(result.error)
        return result
    result.repo_url = repo_url
    result.branch = branch
    log.info("Mapped to %s branch %s", repo_url, branch)

    # Clone the repo
    tmpdir = tempfile.mkdtemp(prefix="cve-fix-")
    try:
        _run(["git", "clone", "--depth=50", "--branch", branch, repo_url, tmpdir])

        # Identify the affected package
        package = _extract_cve_package(ticket.cve_id, ticket.summary)
        if not package:
            result.error = "Could not identify the affected Go package from the CVE summary"
            log.warning(result.error)
            return result
        result.package = package

        # Analyze
        risk, current_ver, govulncheck_out, fix_type = analyze_repo(tmpdir, ticket.cve_id, package)
        result.risk_level = risk
        result.current_version = current_ver
        result.govulncheck_output = govulncheck_out
        result.fix_type = fix_type
        log.info("Risk: %s, Fix type: %s, Current: %s", risk, fix_type, current_ver)

        if risk == "NOT_AFFECTED" or risk == "NOT_GO_PROJECT":
            log.info("Not affected, skipping")
            return result

        if fix_type == "STDLIB":
            result.error = "STDLIB vulnerability — requires Go toolchain update, cannot auto-fix"
            log.warning(result.error)
            return result

        # TODO: look up the fixed version from the Go vuln database
        # For now we log that the fixed version needs manual input
        fixed_version = ""
        if not fixed_version:
            # Try to extract from govulncheck output
            fix_match = re.search(r"Fixed in:\s*(v[\d.]+\S*)", govulncheck_out)
            if fix_match:
                fixed_version = fix_match.group(1)
        result.fixed_version = fixed_version

        if not fixed_version:
            result.error = "Could not determine fixed version — manual intervention needed"
            log.warning(result.error)
            return result

        # Apply fix
        if not apply_fix(tmpdir, package, fixed_version):
            result.error = "Failed to apply fix (go get or go mod tidy failed)"
            return result

        # Run tests
        tests_passed, test_output = run_tests(tmpdir)
        if not tests_passed:
            result.error = f"Tests failed after applying fix:\n{test_output[:500]}"
            log.warning(result.error)
            return result

        # Create PR
        pr_url = create_pr(tmpdir, ticket, package, current_ver, fixed_version, risk)
        result.pr_url = pr_url

        # Comment on Jira
        if pr_url and not pr_url.startswith("[DRY RUN]"):
            comment = (
                f"CVE Bot Analysis:\n"
                f"- Risk: {risk}\n"
                f"- Package: {package} {current_ver} → {fixed_version}\n"
                f"- PR: {pr_url}\n"
            )
            _jira_add_comment(ticket.key, comment)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return result


def main():
    if not JIRA_USER or not JIRA_TOKEN:
        log.error("JIRA_USERNAME and JIRA_API_TOKEN are required")
        sys.exit(1)

    if not TEAM_COMPONENTS:
        log.error("TEAM_COMPONENTS is required (comma-separated Jira components)")
        sys.exit(1)

    log.info("CVE Bot starting (dry_run=%s)", DRY_RUN)
    log.info("Watching components: %s", TEAM_COMPONENTS)

    tickets = fetch_new_cve_tickets()
    if not tickets:
        log.info("No new CVE tickets found")
        return

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    results = []

    for ticket in tickets:
        result = process_ticket(ticket)
        results.append(result)

        status = "PR_CREATED" if result.pr_url else result.risk_level
        if result.error:
            status = f"ERROR: {result.error[:80]}"
        log.info(
            "%s | %s | %s | %s",
            ticket.key, ticket.cve_id, status,
            result.pr_url or "no PR",
        )

    # Write summary
    summary = {
        "total_tickets": len(tickets),
        "results": [
            {
                "ticket": r.ticket.key,
                "cve": r.ticket.cve_id,
                "risk": r.risk_level,
                "fix_type": r.fix_type,
                "pr_url": r.pr_url,
                "error": r.error,
            }
            for r in results
        ],
    }
    summary_file = RESULTS_DIR / "summary.json"
    summary_file.write_text(json.dumps(summary, indent=2))
    log.info("Summary written to %s", summary_file)

    # Print summary table
    print("\n" + "=" * 70)
    print("CVE Bot Summary")
    print("=" * 70)
    for r in results:
        icon = "✓" if r.pr_url else ("⚠" if r.error else "—")
        print(f"  {icon} {r.ticket.key} ({r.ticket.cve_id}): {r.risk_level}")
        if r.pr_url:
            print(f"    PR: {r.pr_url}")
        if r.error:
            print(f"    Error: {r.error[:80]}")
    print("=" * 70)


if __name__ == "__main__":
    main()
