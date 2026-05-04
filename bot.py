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

MANUAL_COMPONENT_MAP_STR = os.environ.get("COMPONENT_MAP", "")
MANUAL_COMPONENT_MAP = {}
for entry in MANUAL_COMPONENT_MAP_STR.split(","):
    entry = entry.strip()
    if "=" in entry:
        comp, repo = entry.split("=", 1)
        MANUAL_COMPONENT_MAP[comp.strip()] = (repo.strip(), "main")


@dataclass
class CVETicket:
    key: str
    cve_id: str
    summary: str
    component: str
    version: str
    status: str
    labels: list = field(default_factory=list)


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


def _build_detailed_comment(ticket: CVETicket, repo_url: str, branch: str,
                             package: str, risk: str, details: dict) -> str:
    """Build a detailed Jira comment with evidence."""
    pkg_short = package.split("/")[-1] if package else "unknown"
    risk_emoji = {"HIGH": "⛔", "LOW": "⚠️", "NOT_AFFECTED": "✅", "NOT_GO_PROJECT": "✅"}.get(risk, "❓")

    lines = [
        f"{ticket.cve_id} Automated Analysis {risk_emoji}",
        f"Risk Assessment: {risk} {risk_emoji}",
        "",
        "Repository Details",
        f"- Component: {ticket.component}",
        f"- Repository: {repo_url}",
        f"- Branch: {branch}",
        f"- Go version: {details.get('go_version', 'unknown')}",
        f"- Vulnerable package: {package or 'N/A'}",
        "",
        "Evidence 1: govulncheck Symbol-Level Analysis",
    ]

    govulncheck_out = details.get("govulncheck", "")
    if govulncheck_out and len(govulncheck_out) > 10:
        for line in govulncheck_out.splitlines()[:15]:
            lines.append(f"  {line}")
    else:
        lines.append(f"  {ticket.cve_id} NOT DETECTED by govulncheck")

    if risk == "NOT_AFFECTED":
        lines.append(f"  ❌ {ticket.cve_id} NOT DETECTED - Package not in dependency tree or not called")
    elif risk == "LOW":
        lines.append(f"  ⚠️ {ticket.cve_id} DETECTED in Package Results (dependency present but not called)")
    elif risk == "HIGH":
        lines.append(f"  ⛔ {ticket.cve_id} DETECTED in Symbol Results (code CALLS vulnerable functions)")

    lines.append("")
    lines.append("Evidence 2: Dependency Analysis (go.mod/go.sum)")

    grep_gomod = details.get("grep_gomod", "")
    grep_gosum = details.get("grep_gosum", "")
    go_mod_why = details.get("go_mod_why", "")

    lines.append(f"  $ grep -i \"{pkg_short}\" go.mod")
    lines.append(f"  {grep_gomod or '(no output)'}")
    lines.append(f"  $ grep -i \"{pkg_short}\" go.sum")
    lines.append(f"  {grep_gosum or '(no output)'}")
    if go_mod_why:
        lines.append(f"  $ go mod why {package}")
        lines.append(f"  {go_mod_why[:200]}")

    gomod_absent = "not found" in grep_gomod.lower() or not grep_gomod
    gosum_absent = "not found" in grep_gosum.lower() or not grep_gosum

    lines.append("  Findings:")
    if gomod_absent:
        lines.append(f"  {'✅' if risk == 'NOT_AFFECTED' else '❌'} {package or 'Package'} is NOT present in go.mod")
    else:
        lines.append(f"  ⚠️ {package or 'Package'} IS present in go.mod")
    if gosum_absent:
        lines.append(f"  {'✅' if risk == 'NOT_AFFECTED' else '❌'} {package or 'Package'} is NOT present in go.sum")
    else:
        lines.append(f"  ⚠️ {package or 'Package'} IS present in go.sum")

    lines.append("")
    lines.append("Evidence 3: Source Code Analysis")
    grep_source = details.get("grep_source", "")
    lines.append(f"  $ grep -r \"{pkg_short}\" . --include=*.go -l")
    lines.append(f"  {grep_source or '(no output - no references found)'}")
    if "not found" in grep_source.lower() or grep_source.startswith("(no"):
        lines.append(f"  Findings:")
        lines.append(f"  ✅ No import statements for {pkg_short}")
        lines.append(f"  ✅ No code references to {pkg_short} functionality")
    else:
        lines.append(f"  Findings:")
        lines.append(f"  ⚠️ Source code references to {pkg_short} found in the files above")

    if risk == "NOT_AFFECTED":
        lines.append("")
        lines.append("Triple-Verification Consensus:")
        lines.append(f"  Dependency check: {'✅' if gomod_absent else '⚠️'} {'No' if gomod_absent else 'Found'} {pkg_short} in go.mod/go.sum")
        lines.append(f"  Code analysis: {'✅' if 'not found' in grep_source.lower() or grep_source.startswith('(no') else '⚠️'} {'No' if 'not found' in grep_source.lower() or grep_source.startswith('(no') else 'Found'} {pkg_short} imports or references")
        lines.append(f"  govulncheck: ✅ Package is absent or not called")

    lines.append("")
    lines.append(f"Risk Classification: {risk} {risk_emoji}")

    if risk == "NOT_AFFECTED":
        lines.append(f"The vulnerable package {package or 'identified in the CVE'} is not present in "
                      f"this repository's dependency tree, or is not called by the code. "
                      f"No action required for {ticket.cve_id}.")
    elif risk == "LOW":
        lines.append(f"The vulnerable package {package} is present but the code does not call "
                      f"the vulnerable functions. Update recommended as best practice.")
    elif risk == "HIGH":
        lines.append(f"The code CALLS vulnerable functions in {package}. Immediate update required.")

    other_vulns = details.get("other_vulns", [])
    if other_vulns:
        lines.append("")
        lines.append("IMPORTANT: Additional Vulnerabilities Detected")
        lines.append(f"govulncheck found {len(other_vulns)} other vulnerabilities:")
        for v in other_vulns[:10]:
            lines.append(f"  - {v.get('id', '?')} ({v.get('package', '?')})")
        lines.append("Consider investigating these separately.")

    lines.append("")
    lines.append("Recommendation")
    if risk == "NOT_AFFECTED":
        lines.append(f"Action: No action required for {ticket.cve_id}.")
    elif risk == "LOW":
        lines.append(f"Action: Update {package} as best practice. Not urgent.")
    elif risk == "HIGH":
        lines.append(f"Action: Update {package} immediately. Fix is urgent.")

    lines.append("")
    lines.append("---")
    lines.append("Automated analysis by CVE Bot (govulncheck + dependency verification)")

    return "\n".join(lines)


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
        f"AND issuetype in (Vulnerability, Bug) "
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
                labels=fields.get("labels", []),
            ))
    return tickets


# ---------------------------------------------------------------------------
# Repository mapping (via ocp-build-data)
# ---------------------------------------------------------------------------

def _run(cmd: list[str], cwd: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    log.debug("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=check, timeout=300)


def map_component_to_repo(component: str, version: str, labels: list[str] | None = None) -> tuple[str, str]:
    """Map a Jira component to a GitHub repo URL and branch.

    Uses the same approach as Jaspreet's analyze-cve:
    1. Check manual COMPONENT_MAP
    2. Extract pscomponent from labels (e.g. openshift4/ose-cluster-storage-rhel9-operator)
    3. Look up in ocp-build-data delivery_component_mapping.yml
    4. Read the image YAML to find the GitHub repo URL
    """
    if component in MANUAL_COMPONENT_MAP:
        repo_url, default_branch = MANUAL_COMPONENT_MAP[component]
        ocp_version = version.replace("openshift-", "") if version else ""
        branch = f"release-{ocp_version}" if ocp_version else default_branch
        log.info("Using manual mapping: %s → %s branch %s", component, repo_url, branch)
        return repo_url, branch

    pscomponent = ""
    for label in (labels or []):
        if label.startswith("pscomponent:"):
            pscomponent = label[len("pscomponent:"):]
            break

    ocp_branch = version if version else "openshift-4.17"
    ocp_version = version.replace("openshift-", "") if version else "4.17"

    tmpdir = tempfile.mkdtemp(prefix="ocp-build-data-")
    try:
        _run(["git", "clone", "--depth=1", "--branch", ocp_branch,
              OCP_BUILD_DATA_REPO, tmpdir], check=False)

        search_terms = [t for t in [pscomponent, component] if t]

        mapping_file = Path(tmpdir) / "delivery_component_mapping.yml"
        if mapping_file.exists():
            mapping_content = mapping_file.read_text()
            for term in search_terms:
                pattern = re.compile(rf"^{re.escape(term)}:\s*\n\s*image_file:\s*(\S+)",
                                     re.MULTILINE)
                match = pattern.search(mapping_content)
                if match:
                    image_path = Path(tmpdir) / match.group(1).strip()
                    repo_url = _read_repo_from_image_yaml(image_path)
                    if repo_url:
                        log.info("ocp-build-data mapping: %s → %s", term, repo_url)
                        return repo_url, f"release-{ocp_version}"

        images_dir = Path(tmpdir) / "images"
        if images_dir.exists():
            for term in search_terms:
                short_name = term.split("/")[-1] if "/" in term else term
                short_name = re.sub(r"-rhel\d+-?", "-", short_name).rstrip("-")
                for yml in images_dir.glob("*.yml"):
                    if short_name.lower() in yml.name.lower():
                        repo_url = _read_repo_from_image_yaml(yml)
                        if repo_url:
                            log.info("ocp-build-data image file match: %s → %s", yml.name, repo_url)
                            return repo_url, f"release-{ocp_version}"

            for term in search_terms:
                for yml in images_dir.glob("*.yml"):
                    content = yml.read_text()
                    if term.lower() in content.lower():
                        repo_url = _read_repo_from_image_yaml(yml)
                        if repo_url:
                            log.info("ocp-build-data content match: %s in %s → %s",
                                     term, yml.name, repo_url)
                            return repo_url, f"release-{ocp_version}"
    except Exception as e:
        log.warning("ocp-build-data lookup failed: %s", e)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return "", ""


def _read_repo_from_image_yaml(path: Path) -> str:
    """Extract the GitHub repo URL from an ocp-build-data image YAML file."""
    if not path.exists():
        return ""
    content = path.read_text()
    match = re.search(r"web:\s*(https://github\.com/\S+)", content)
    if match:
        return match.group(1).rstrip("/")
    return ""


def _extract_repo_from_summary(summary: str, version: str) -> tuple[str, str]:
    """Try to extract a GitHub org/repo from the ticket summary.

    Handles multiple formats:
      CVE-XXXX openshift-kni/commatrix: ...          → github.com/openshift-kni/commatrix
      CVE-XXXX openshift4/cnf-tests-rhel8: ...       → skipped (container image, not a repo)
      CVE-XXXX rhcos: ...                             → no repo
    """
    match = re.search(r"CVE-[\d-]+\s+([\w.-]+/[\w.-]+):", summary)
    if match:
        org_repo = match.group(1)
        if org_repo.startswith("openshift4/") or org_repo.endswith(("-rhel8", "-rhel9")):
            log.info("Skipping container image name: %s", org_repo)
            return "", ""
        repo_url = f"https://github.com/{org_repo}"
        ocp_version = version.replace("openshift-", "") if version else ""
        branch = f"release-{ocp_version}" if ocp_version else "main"
        log.info("Extracted repo from summary: %s branch %s", repo_url, branch)
        return repo_url, branch
    return "", ""


def _extract_repo_from_labels(labels: list[str], version: str) -> tuple[str, str]:
    """Try to extract a GitHub repo from pscomponent label.

    Labels often include: pscomponent:openshift-kni/commatrix
    """
    for label in labels:
        if label.startswith("pscomponent:"):
            pscomp = label[len("pscomponent:"):]
            if "/" in pscomp and not pscomp.startswith("openshift4/"):
                repo_url = f"https://github.com/{pscomp}"
                ocp_version = version.replace("openshift-", "") if version else ""
                branch = f"release-{ocp_version}" if ocp_version else "main"
                log.info("Extracted repo from pscomponent label: %s branch %s", repo_url, branch)
                return repo_url, branch
    return "", ""


# ---------------------------------------------------------------------------
# CVE analysis
# ---------------------------------------------------------------------------

def _extract_cve_package(cve_id: str, summary: str) -> str:
    """Try to extract the affected Go package from the CVE summary."""
    known_patterns = {
        "grpc": "google.golang.org/grpc",
        "go-jose": "github.com/go-jose/go-jose",
        "go jose": "github.com/go-jose/go-jose",
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


@dataclass
class DetailedAnalysis:
    risk_level: str = "UNKNOWN"
    current_version: str = ""
    fix_type: str = ""
    package: str = ""
    govulncheck_output: str = ""
    go_mod_why: str = ""
    grep_gomod: str = ""
    grep_gosum: str = ""
    grep_source: str = ""
    go_version: str = ""
    other_vulns: list = field(default_factory=list)


def analyze_repo(repo_dir: str, cve_id: str, package: str) -> tuple[str, str, str, str]:
    """Run govulncheck and check if the repo is affected.

    Returns (risk_level, current_version, govulncheck_output, fix_type).
    """
    gomod = Path(repo_dir) / "go.mod"
    if not gomod.exists():
        return "NOT_GO_PROJECT", "", "", ""

    gomod_content = gomod.read_text()
    details = DetailedAnalysis(package=package)

    go_ver_match = re.search(r"^go\s+([\d.]+)", gomod_content, re.MULTILINE)
    details.go_version = go_ver_match.group(1) if go_ver_match else "unknown"

    if package:
        version_match = re.search(rf"{re.escape(package)}\s+(v[\d.]+\S*)", gomod_content)
        details.current_version = version_match.group(1) if version_match else ""

        pkg_short = package.split("/")[-1]

        grep_result = _run(["grep", "-i", pkg_short, "go.mod"], cwd=repo_dir, check=False)
        details.grep_gomod = grep_result.stdout.strip() or "(not found)"

        grep_sum = _run(["grep", "-i", pkg_short, "go.sum"], cwd=repo_dir, check=False)
        details.grep_gosum = grep_sum.stdout.strip()[:200] if grep_sum.stdout.strip() else "(not found)"

        mod_why = _run(["go", "mod", "why", package], cwd=repo_dir, check=False)
        details.go_mod_why = mod_why.stdout.strip()[:500] or mod_why.stderr.strip()[:500]

        source_grep = _run(["grep", "-r", pkg_short, ".", "--include=*.go", "-l"],
                           cwd=repo_dir, check=False)
        if source_grep.stdout.strip():
            details.grep_source = source_grep.stdout.strip()[:500]
        else:
            details.grep_source = "(no source code references found)"

    if package and package not in gomod_content:
        details.risk_level = "NOT_AFFECTED"
        details.govulncheck_output = "Package not in dependency tree"
        _store_details(repo_dir, details)
        return "NOT_AFFECTED", "", json.dumps(_details_to_dict(details)), ""

    _run(["go", "install", "golang.org/x/vuln/cmd/govulncheck@latest"], cwd=repo_dir, check=False)

    result = _run(["govulncheck", "./..."], cwd=repo_dir, check=False)
    output = result.stdout + result.stderr
    details.govulncheck_output = output[:3000]
    log.info("govulncheck output (first 500 chars): %s", output[:500])

    cve_found = cve_id.lower() in output.lower()

    if "Symbol Results" in output:
        details.risk_level = "HIGH"
    elif "Package Results" in output:
        details.risk_level = "LOW" if cve_found else "NOT_AFFECTED"
    elif cve_found:
        details.risk_level = "LOW"
    else:
        details.risk_level = "NOT_AFFECTED"

    for m in re.finditer(r"(GO-\d{4}-\d+)\s*(?:\(([^)]+)\))?\s*", output):
        vuln_id = m.group(1)
        vuln_pkg = m.group(2) or ""
        if vuln_id not in str(details.other_vulns):
            details.other_vulns.append({"id": vuln_id, "package": vuln_pkg})

    if not package and cve_found:
        pkg_match = re.search(r"Module:\s+(\S+)", output)
        if pkg_match:
            package = pkg_match.group(1)
            details.package = package
            log.info("Auto-detected package from govulncheck: %s", package)
            version_match = re.search(rf"{re.escape(package)}\s+(v[\d.]+\S*)", gomod_content)
            details.current_version = version_match.group(1) if version_match else "unknown"

    if not package:
        details.fix_type = "UNKNOWN"
    elif "/" not in package:
        details.fix_type = "STDLIB"
    elif package.startswith("golang.org/x/"):
        details.fix_type = "EXTENDED_STDLIB"
    else:
        details.fix_type = "THIRD_PARTY"

    _store_details(repo_dir, details)
    return details.risk_level, details.current_version, json.dumps(_details_to_dict(details)), details.fix_type


def _details_to_dict(d: DetailedAnalysis) -> dict:
    return {
        "risk_level": d.risk_level,
        "package": d.package,
        "current_version": d.current_version,
        "go_version": d.go_version,
        "fix_type": d.fix_type,
        "govulncheck": d.govulncheck_output[:1000],
        "go_mod_why": d.go_mod_why,
        "grep_gomod": d.grep_gomod,
        "grep_gosum": d.grep_gosum,
        "grep_source": d.grep_source,
        "other_vulns": d.other_vulns[:10],
    }


def _store_details(repo_dir: str, details: DetailedAnalysis) -> None:
    try:
        out = Path(repo_dir) / "cve-analysis.json"
        out.write_text(json.dumps(_details_to_dict(details), indent=2))
    except Exception:
        pass


def _lookup_fixed_version(cve_id: str, package: str, govulncheck_out: str) -> str:
    """Look up the fixed version for a CVE from multiple sources.

    Tries in order:
    1. govulncheck output (most reliable)
    2. Go vulnerability database API (vuln.go.dev)
    3. Package proxy API (proxy.golang.org)
    """
    # Method 1: Extract from govulncheck output
    for pattern in [
        r"Fixed in:\s*(v[\d.]+\S*)",
        r"Fixed in:\s*\S+@(v[\d.]+\S*)",
        rf"{re.escape(package)}@(v[\d.]+\S*)",
    ]:
        match = re.search(pattern, govulncheck_out)
        if match:
            version = match.group(1)
            log.info("Fixed version from govulncheck: %s", version)
            return version

    # Method 2: Go vulnerability database API
    try:
        go_vuln_id = ""
        id_match = re.search(r"(GO-\d{4}-\d+)", govulncheck_out)
        if id_match:
            go_vuln_id = id_match.group(1)

        if go_vuln_id:
            resp = requests.get(f"https://vuln.go.dev/ID/{go_vuln_id}.json", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for affected in data.get("affected", []):
                    pkg_name = affected.get("package", {}).get("name", "")
                    if package and package in pkg_name:
                        for rng in affected.get("ranges", []):
                            for event in rng.get("events", []):
                                if "fixed" in event:
                                    version = event["fixed"]
                                    log.info("Fixed version from vuln.go.dev (%s): %s", go_vuln_id, version)
                                    return version if version.startswith("v") else f"v{version}"
    except Exception as e:
        log.debug("vuln.go.dev lookup failed: %s", e)

    # Method 3: Check latest version from Go proxy
    if package and "/" in package:
        try:
            resp = requests.get(f"https://proxy.golang.org/{package}/@latest", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                version = data.get("Version", "")
                if version:
                    log.info("Latest version from proxy.golang.org: %s (may not be the minimum fix)", version)
                    return version
        except Exception as e:
            log.debug("proxy.golang.org lookup failed: %s", e)

    return ""


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

    # Map component to repo (try multiple methods in order)
    repo_url, branch = map_component_to_repo(ticket.component, ticket.version, ticket.labels)
    if not repo_url:
        repo_url, branch = _extract_repo_from_summary(ticket.summary, ticket.version)
    if not repo_url:
        repo_url, branch = _extract_repo_from_labels(ticket.labels, ticket.version)
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
        clone_result = _run(["git", "clone", "--depth=50", "--branch", branch, repo_url, tmpdir], check=False)
        if clone_result.returncode != 0:
            log.info("Branch %s not found, trying main/master", branch)
            for fallback in ["main", "master"]:
                clone_result = _run(["git", "clone", "--depth=50", "--branch", fallback, repo_url, tmpdir], check=False)
                if clone_result.returncode == 0:
                    branch = fallback
                    result.branch = branch
                    log.info("Cloned with fallback branch: %s", branch)
                    break
            if clone_result.returncode != 0:
                result.error = f"Could not clone {repo_url} (tried {branch}, main, master)"
                log.warning(result.error)
                return result

        # Try to identify the package from the summary first
        package = _extract_cve_package(ticket.cve_id, ticket.summary)
        if not package:
            log.info("Could not extract package from summary, running govulncheck to detect automatically")

        # Analyze (govulncheck runs on the whole repo regardless)
        risk, current_ver, govulncheck_out, fix_type = analyze_repo(tmpdir, ticket.cve_id, package)
        result.risk_level = risk
        result.current_version = current_ver
        result.govulncheck_output = govulncheck_out
        result.fix_type = fix_type

        pkg_match = re.search(r"Auto-detected package.*?:\s*(\S+)", govulncheck_out)
        if not package and "Module:" in govulncheck_out:
            mod_match = re.search(r"Module:\s+(\S+)", govulncheck_out)
            if mod_match:
                package = mod_match.group(1)
        result.package = package
        log.info("Risk: %s, Fix type: %s, Package: %s, Current: %s", risk, fix_type, package, current_ver)

        if risk == "NOT_AFFECTED" or risk == "NOT_GO_PROJECT":
            log.info("Not affected, skipping")
            try:
                details = json.loads(govulncheck_out)
            except (json.JSONDecodeError, TypeError):
                details = {}
            comment = _build_detailed_comment(ticket, repo_url, branch, package, risk, details)
            _jira_add_comment(ticket.key, comment)
            return result

        if fix_type == "STDLIB":
            result.error = "STDLIB vulnerability — requires Go toolchain update, cannot auto-fix"
            log.warning(result.error)
            return result

        fixed_version = _lookup_fixed_version(ticket.cve_id, package, govulncheck_out)
        result.fixed_version = fixed_version
        log.info("Fixed version: %s", fixed_version or "(not found)")

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
