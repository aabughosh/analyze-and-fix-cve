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
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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

_ocp_build_data_cache: dict[str, str] = {}


def _http_session() -> requests.Session:
    """Return a requests session with automatic retries on transient errors."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


_session = _http_session()


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


@dataclass
class OSVData:
    """Pre-validated CVE data from the OSV API."""
    go_vuln_id: str = ""
    aliases: list = field(default_factory=list)
    packages: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# OSV pre-validation
# ---------------------------------------------------------------------------

def osv_lookup_cve(cve_id: str) -> OSVData | None:
    """Validate a CVE against the OSV database and extract package/version info.

    Returns None if the CVE is not tracked.
    """
    try:
        resp = _session.get(f"https://api.osv.dev/v1/vulns/{cve_id}", timeout=15)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        log.warning("OSV API lookup failed for %s: %s", cve_id, e)
        return None

    result = OSVData()
    result.aliases = data.get("aliases", [])

    for alias in result.aliases:
        if alias.startswith("GO-"):
            result.go_vuln_id = alias
            break

    for affected in data.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != "Go":
            continue
        pkg_name = pkg.get("name", "")
        fixed_version = ""
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    v = event["fixed"]
                    fixed_version = v if v.startswith("v") else f"v{v}"
        if pkg_name:
            result.packages.append({"name": pkg_name, "fixed": fixed_version})

    return result


# ---------------------------------------------------------------------------
# Jira helpers
# ---------------------------------------------------------------------------

def _jira_search(jql: str, max_results: int = 50) -> list[dict]:
    resp = _session.post(
        f"{JIRA_URL}/rest/api/3/search/jql",
        json={"jql": jql, "fields": ["summary", "components", "labels", "status"], "maxResults": max_results},
        auth=(JIRA_USER, JIRA_TOKEN),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("issues", [])


def _text_to_adf(text: str) -> dict:
    """Convert a multi-line plain text string into Jira ADF with one paragraph per line."""
    paragraphs = []
    for line in text.split("\n"):
        if line:
            paragraphs.append({
                "type": "paragraph",
                "content": [{"type": "text", "text": line}],
            })
        else:
            paragraphs.append({"type": "paragraph", "content": []})
    return {"type": "doc", "version": 1, "content": paragraphs}


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
    no_source_refs = "not found" in grep_source.lower() or grep_source.startswith("(no")
    if no_source_refs:
        lines.append("  Findings:")
        lines.append(f"  ✅ No import statements for {pkg_short}")
        lines.append(f"  ✅ No code references to {pkg_short} functionality")
    else:
        lines.append("  Findings:")
        lines.append(f"  ⚠️ Source code references to {pkg_short} found in the files above")

    if risk == "NOT_AFFECTED":
        lines.append("")
        lines.append("Triple-Verification Consensus:")
        dep_ok = "✅" if gomod_absent else "⚠️"
        dep_word = "No" if gomod_absent else "Found"
        code_ok = "✅" if no_source_refs else "⚠️"
        code_word = "No" if no_source_refs else "Found"
        lines.append(f"  Dependency check: {dep_ok} {dep_word} {pkg_short} in go.mod/go.sum")
        lines.append(f"  Code analysis: {code_ok} {code_word} {pkg_short} imports or references")
        lines.append("  govulncheck: ✅ Package is absent or not called")

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
    resp = _session.post(
        f"{JIRA_URL}/rest/api/3/issue/{issue_key}/comment",
        json={"body": _text_to_adf(body)},
        auth=(JIRA_USER, JIRA_TOKEN),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=30,
    )
    if resp.status_code >= 400:
        log.warning("Failed to comment on %s: %s %s", issue_key, resp.status_code, resp.text[:200])


def _jira_add_label(issue_key: str, label: str) -> None:
    if DRY_RUN:
        log.info("[DRY RUN] Would add label '%s' to %s", label, issue_key)
        return
    resp = _session.put(
        f"{JIRA_URL}/rest/api/3/issue/{issue_key}",
        json={"update": {"labels": [{"add": label}]}},
        auth=(JIRA_USER, JIRA_TOKEN),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=30,
    )
    if resp.status_code >= 400:
        log.warning("Failed to add label '%s' to %s: %s %s",
                     label, issue_key, resp.status_code, resp.text[:200])


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


def _get_ocp_build_data(ocp_branch: str) -> str | None:
    """Return path to a cached ocp-build-data clone for the given branch."""
    if ocp_branch in _ocp_build_data_cache:
        cached = _ocp_build_data_cache[ocp_branch]
        if Path(cached).exists():
            return cached

    tmpdir = tempfile.mkdtemp(prefix="ocp-build-data-")
    result = _run(["git", "clone", "--depth=1", "--branch", ocp_branch,
                   OCP_BUILD_DATA_REPO, tmpdir], check=False)
    if result.returncode != 0:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None
    _ocp_build_data_cache[ocp_branch] = tmpdir
    return tmpdir


def cleanup_ocp_build_data_cache() -> None:
    """Remove all cached ocp-build-data clones."""
    for path in _ocp_build_data_cache.values():
        shutil.rmtree(path, ignore_errors=True)
    _ocp_build_data_cache.clear()


def map_component_to_repo(component: str, version: str, labels: list[str] | None = None) -> tuple[str, str]:
    """Map a Jira component to a GitHub repo URL and branch."""
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

    try:
        tmpdir = _get_ocp_build_data(ocp_branch)
        if not tmpdir:
            return "", ""

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
    """Try to extract a GitHub org/repo from the ticket summary."""
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
    """Try to extract a GitHub repo from pscomponent label."""
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


def _extract_package_from_summary(summary: str) -> str:
    """Try to extract a Go package path from a Jira ticket summary.

    Looks for patterns like golang.org/x/net, github.com/foo/bar, etc.
    """
    match = re.search(r"((?:golang\.org|github\.com|google\.golang\.org|go\.etcd\.io)/\S+)", summary)
    if match:
        pkg = match.group(1).rstrip(".,;:)")
        return pkg
    return ""


def _parse_govulncheck_json(raw_output: str, cve_id: str, osv_data: OSVData | None,
                            fallback_package: str = "") -> dict:
    """Parse govulncheck JSON output and classify risk for the target CVE.

    First tries precise matching by CVE ID and aliases. If nothing matches and
    fallback_package is set, checks if any finding affects that package.

    Returns dict with keys: risk_level, package, fixed_version,
    other_vulns, matched_vuln_summary, matched_by_fallback.
    """
    target_ids = {cve_id.upper()}
    if osv_data:
        target_ids.update(a.upper() for a in osv_data.aliases)
        if osv_data.go_vuln_id:
            target_ids.add(osv_data.go_vuln_id.upper())

    result = {
        "risk_level": "NOT_AFFECTED",
        "package": "",
        "fixed_version": "",
        "other_vulns": [],
        "matched_vuln_summary": "",
        "matched_by_fallback": False,
    }

    osv_entries: dict[str, dict] = {}
    findings: list[dict] = []

    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        if "osv" in obj:
            entry = obj["osv"]
            osv_entries[entry.get("id", "")] = entry
        elif "finding" in obj:
            findings.append(obj["finding"])

    # Collect per-finding data for both precise and fallback matching
    parsed_findings: list[dict] = []
    for finding in findings:
        osv_id = finding.get("osv", "")
        trace = finding.get("trace", [])

        entry = osv_entries.get(osv_id, {})
        aliases = [a.upper() for a in entry.get("aliases", [])]
        all_ids = {osv_id.upper()} | set(aliases)

        has_symbol_trace = any(t.get("function") for t in trace)

        vuln_module = ""
        for t in trace:
            if t.get("module") and t["module"] != "stdlib":
                vuln_module = t["module"]
                break

        parsed_findings.append({
            "osv_id": osv_id,
            "entry": entry,
            "all_ids": all_ids,
            "has_symbol_trace": has_symbol_trace,
            "vuln_module": vuln_module,
            "is_target": bool(all_ids & target_ids),
        })

    # Pass 1: precise match by CVE ID / aliases
    for pf in parsed_findings:
        if pf["is_target"]:
            result["package"] = pf["vuln_module"]
            result["risk_level"] = "HIGH" if pf["has_symbol_trace"] else "LOW"

            for affected in pf["entry"].get("affected", []):
                pkg = affected.get("package", {})
                if pkg.get("name", "") == pf["vuln_module"] or not pf["vuln_module"]:
                    for rng in affected.get("ranges", []):
                        for event in rng.get("events", []):
                            if "fixed" in event:
                                v = event["fixed"]
                                result["fixed_version"] = v if v.startswith("v") else f"v{v}"

            cve_ids = [a for a in pf["entry"].get("aliases", []) if a.startswith("CVE-")]
            result["matched_vuln_summary"] = (
                f"{pf['osv_id']} ({', '.join(cve_ids)}): "
                f"{'Symbol-level call found' if pf['has_symbol_trace'] else 'Package imported but not called'}"
            )
        else:
            cve_ids = [a for a in pf["entry"].get("aliases", []) if a.startswith("CVE-")]
            vuln_info = {"id": pf["osv_id"], "package": pf["vuln_module"], "cve_ids": cve_ids}
            if vuln_info not in result["other_vulns"]:
                result["other_vulns"].append(vuln_info)

    # Pass 2: fallback — if no precise match, check if any finding affects the
    # package mentioned in the ticket summary
    if result["risk_level"] == "NOT_AFFECTED" and fallback_package:
        best_fallback = None
        for pf in parsed_findings:
            if not pf["vuln_module"]:
                continue
            if (fallback_package == pf["vuln_module"]
                    or fallback_package.startswith(pf["vuln_module"] + "/")
                    or pf["vuln_module"].startswith(fallback_package + "/")):
                if best_fallback is None or (pf["has_symbol_trace"] and not best_fallback["has_symbol_trace"]):
                    best_fallback = pf

        if best_fallback:
            result["package"] = best_fallback["vuln_module"]
            result["risk_level"] = "HIGH" if best_fallback["has_symbol_trace"] else "LOW"
            result["matched_by_fallback"] = True

            for affected in best_fallback["entry"].get("affected", []):
                pkg = affected.get("package", {})
                if pkg.get("name", "") == best_fallback["vuln_module"] or not best_fallback["vuln_module"]:
                    for rng in affected.get("ranges", []):
                        for event in rng.get("events", []):
                            if "fixed" in event:
                                v = event["fixed"]
                                result["fixed_version"] = v if v.startswith("v") else f"v{v}"

            cve_ids = [a for a in best_fallback["entry"].get("aliases", []) if a.startswith("CVE-")]
            result["matched_vuln_summary"] = (
                f"FALLBACK MATCH: {best_fallback['osv_id']} ({', '.join(cve_ids)}) "
                f"affects {best_fallback['vuln_module']}: "
                f"{'Symbol-level call found' if best_fallback['has_symbol_trace'] else 'Package imported but not called'}"
            )
            log.info("Fallback match: %s has vulnerability %s in package %s",
                     fallback_package, best_fallback["osv_id"], best_fallback["vuln_module"])

    return result


def analyze_repo(repo_dir: str, cve_id: str, osv_data: OSVData | None,
                 summary: str = "") -> tuple[str, str, str, str]:
    """Run govulncheck in JSON mode and check if the repo is affected.

    Returns (risk_level, current_version, details_json, fix_type).
    """
    gomod = Path(repo_dir) / "go.mod"
    if not gomod.exists():
        return "NOT_GO_PROJECT", "", "", ""

    gomod_content = gomod.read_text()

    package = ""
    if osv_data and osv_data.packages:
        for pkg_info in osv_data.packages:
            if pkg_info["name"] in gomod_content:
                package = pkg_info["name"]
                break
        if not package:
            package = osv_data.packages[0]["name"]

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

    result = _run(["govulncheck", "-json", "./..."], cwd=repo_dir, check=False)
    raw_output = result.stdout
    details.govulncheck_output = raw_output[:3000]
    log.info("govulncheck JSON output length: %d chars", len(raw_output))

    fallback_pkg = _extract_package_from_summary(summary) if summary else ""
    parsed = _parse_govulncheck_json(raw_output, cve_id, osv_data, fallback_pkg)

    details.risk_level = parsed["risk_level"]
    details.other_vulns = parsed["other_vulns"]

    if parsed["package"]:
        details.package = parsed["package"]
        package = parsed["package"]
        if not details.current_version:
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


def _lookup_fixed_version(cve_id: str, package: str, govulncheck_out: str,
                          osv_data: OSVData | None) -> str:
    """Look up the fixed version from OSV data, govulncheck output, or vuln.go.dev."""
    if osv_data:
        for pkg_info in osv_data.packages:
            if pkg_info["name"] == package and pkg_info["fixed"]:
                log.info("Fixed version from OSV data: %s", pkg_info["fixed"])
                return pkg_info["fixed"]

    for pattern in [
        r"Fixed in:\s*(v[\d.]+[\w.-]*)",
        r"Fixed in:\s*\S+@(v[\d.]+[\w.-]*)",
        rf"{re.escape(package)}@(v[\d.]+[\w.-]*)",
    ]:
        match = re.search(pattern, govulncheck_out)
        if match:
            version = match.group(1).strip()
            log.info("Fixed version from govulncheck: %s", version)
            return version

    try:
        go_vuln_id = osv_data.go_vuln_id if osv_data else ""
        if not go_vuln_id:
            id_match = re.search(r"(GO-\d{4}-\d+)", govulncheck_out)
            if id_match:
                go_vuln_id = id_match.group(1)

        if go_vuln_id:
            resp = _session.get(f"https://vuln.go.dev/ID/{go_vuln_id}.json", timeout=10)
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

    if package and "/" in package:
        try:
            resp = _session.get(f"https://proxy.golang.org/{package}/@latest", timeout=10)
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
    target = f"{package}@{fixed_version}"

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


def _check_existing_pr(branch_name: str, target_repo: str) -> str:
    """Check if a PR already exists for this branch. Returns the URL or empty string."""
    result = _run(
        ["gh", "pr", "list", "--head", branch_name, "--repo", target_repo,
         "--json", "url", "--limit", "1"],
        check=False,
    )
    if result.returncode == 0 and result.stdout.strip():
        try:
            prs = json.loads(result.stdout)
            if prs:
                return prs[0].get("url", "")
        except json.JSONDecodeError:
            pass
    return ""


def create_pr(repo_dir: str, ticket: CVETicket, package: str,
              old_version: str, fixed_version: str, risk: str,
              repo_url: str = "") -> str:
    """Create a branch, commit, push, and open a PR. Returns the PR URL."""
    branch_name = f"fix-{ticket.cve_id.lower()}-{ticket.version}"
    target_repo = repo_url.replace("https://github.com/", "") if repo_url else ""

    if target_repo and not DRY_RUN:
        existing = _check_existing_pr(branch_name, target_repo)
        if existing:
            log.info("PR already exists for branch %s: %s", branch_name, existing)
            return existing

    _run(["git", "config", "user.email", "cve-bot@redhat.com"], cwd=repo_dir, check=False)
    _run(["git", "config", "user.name", "CVE Bot"], cwd=repo_dir, check=False)

    _run(["git", "checkout", "-b", branch_name], cwd=repo_dir, check=False)

    log_result = _run(["git", "log", "--oneline", "-10"], cwd=repo_dir, check=False)
    is_upstream = "UPSTREAM:" in log_result.stdout

    _run(["git", "add", "-A"], cwd=repo_dir)

    if is_upstream:
        msg = f"UPSTREAM: <carry>: Bump {package} to {fixed_version} for {ticket.cve_id}"
    else:
        msg = f"{ticket.key}: Bump {package} to {fixed_version} for {ticket.cve_id}"

    _run(["git", "commit", "-m", msg], cwd=repo_dir, check=False)

    if DRY_RUN:
        log.info("[DRY RUN] Would push branch %s and create PR", branch_name)
        return f"[DRY RUN] PR would be created on branch {branch_name}"

    repo_owner = repo_url.replace("https://github.com/", "").split("/")[0] if repo_url else ""
    gh_user_result = _run(["gh", "api", "user", "-q", ".login"], cwd=repo_dir, check=False)
    gh_user = gh_user_result.stdout.strip() if gh_user_result.returncode == 0 else ""
    is_fork_needed = gh_user and repo_owner and gh_user.lower() != repo_owner.lower()

    if is_fork_needed:
        log.info("No push access to %s, forking to %s", repo_owner, gh_user)
        fork_result = _run(["gh", "repo", "fork", repo_url.replace("https://github.com/", ""),
                            "--clone=false", "--remote=false"], cwd=repo_dir, check=False)
        if fork_result.returncode != 0:
            log.info("Fork may already exist, continuing: %s", fork_result.stderr[:200])

        repo_name = repo_url.replace("https://github.com/", "").split("/")[-1]
        fork_url = f"https://github.com/{gh_user}/{repo_name}"
        gh_token = os.environ.get("GITHUB_TOKEN", "")
        if gh_token:
            auth_fork_url = fork_url.replace("https://github.com/", f"https://x-access-token:{gh_token}@github.com/")
        else:
            auth_fork_url = fork_url
        _run(["git", "remote", "set-url", "origin", auth_fork_url], cwd=repo_dir, check=False)
        log.info("Set push remote to fork: %s", fork_url)

    push_result = _run(["git", "push", "--force", "origin", branch_name], cwd=repo_dir, check=False)
    if push_result.returncode != 0:
        log.error("git push failed: %s", push_result.stderr)
        return ""

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

    if is_fork_needed:
        head_ref = f"{gh_user}:{branch_name}"
    else:
        head_ref = branch_name

    result = _run(
        ["gh", "pr", "create",
         "--head", head_ref,
         "--title", msg,
         "--body", pr_body,
         "--repo", target_repo],
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

    osv_data = osv_lookup_cve(ticket.cve_id)
    if osv_data is None:
        log.info("OSV has no entry for %s — will rely on govulncheck to detect it", ticket.cve_id)
    elif not osv_data.packages:
        log.info("OSV has no Go packages for %s — will rely on govulncheck", ticket.cve_id)
        osv_data = None
    else:
        log.info("OSV pre-validation: %s → %s, packages: %s",
                 ticket.cve_id, osv_data.go_vuln_id,
                 [p["name"] for p in osv_data.packages])

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

    tmpdir = tempfile.mkdtemp(prefix="cve-fix-")
    try:
        auth_repo_url = repo_url
        gh_token = os.environ.get("GITHUB_TOKEN", "")
        if gh_token and "github.com" in repo_url:
            auth_repo_url = repo_url.replace("https://github.com/", f"https://x-access-token:{gh_token}@github.com/")

        clone_result = _run(["git", "clone", "--depth=50", "--branch", branch, auth_repo_url, tmpdir], check=False)
        if clone_result.returncode != 0:
            log.info("Branch %s not found, trying main/master", branch)
            for fallback in ["main", "master"]:
                clone_result = _run(["git", "clone", "--depth=50", "--branch", fallback, auth_repo_url, tmpdir], check=False)
                if clone_result.returncode == 0:
                    branch = fallback
                    result.branch = branch
                    log.info("Cloned with fallback branch: %s", branch)
                    break
            if clone_result.returncode != 0:
                result.error = f"Could not clone {repo_url} (tried {branch}, main, master)"
                log.warning(result.error)
                return result

        risk, current_ver, govulncheck_out, fix_type = analyze_repo(tmpdir, ticket.cve_id, osv_data, ticket.summary)
        result.risk_level = risk
        result.current_version = current_ver
        result.govulncheck_output = govulncheck_out
        result.fix_type = fix_type

        package = ""
        try:
            details_dict = json.loads(govulncheck_out)
            package = details_dict.get("package", "")
        except (json.JSONDecodeError, TypeError):
            pass
        if not package and osv_data and osv_data.packages:
            package = osv_data.packages[0]["name"]
        result.package = package
        log.info("Risk: %s, Fix type: %s, Package: %s, Current: %s", risk, fix_type, package, current_ver)

        if risk in ("NOT_AFFECTED", "NOT_GO_PROJECT"):
            log.info("Not affected, skipping")
            try:
                details = json.loads(govulncheck_out)
            except (json.JSONDecodeError, TypeError):
                details = {}
            comment = _build_detailed_comment(ticket, repo_url, branch, package, risk, details)
            _jira_add_comment(ticket.key, comment)
            _jira_add_label(ticket.key, "cve-bot-processed")
            return result

        if fix_type == "STDLIB":
            result.error = "STDLIB vulnerability — requires Go toolchain update, cannot auto-fix"
            log.warning(result.error)
            comment = (
                f"CVE Bot Analysis for {ticket.cve_id}:\n"
                f"Risk: {risk}\n"
                f"Package: {package}\n\n"
                f"This is a standard library (STDLIB) vulnerability that requires a Go toolchain update.\n"
                f"Cannot auto-fix — please coordinate with the openshift-golang-builder-container team."
            )
            _jira_add_comment(ticket.key, comment)
            _jira_add_label(ticket.key, "cve-bot-processed")
            return result

        fixed_version = _lookup_fixed_version(ticket.cve_id, package, govulncheck_out, osv_data)
        result.fixed_version = fixed_version
        log.info("Fixed version: %s", fixed_version or "(not found)")

        if not fixed_version:
            result.error = "Could not determine fixed version — manual intervention needed"
            log.warning(result.error)
            return result

        if not apply_fix(tmpdir, package, fixed_version):
            result.error = "Failed to apply fix (go get or go mod tidy failed)"
            return result

        log.info("Running go test ./...")
        tests_passed, test_output = run_tests(tmpdir)
        if not tests_passed:
            result.error = f"Tests failed after applying fix:\n{test_output[:500]}"
            log.warning(result.error)
            return result
        log.info("Tests passed ✓")

        pr_url = create_pr(tmpdir, ticket, package, current_ver, fixed_version, risk, repo_url)
        result.pr_url = pr_url

        if pr_url and not pr_url.startswith("[DRY RUN]"):
            comment = (
                f"CVE Bot Analysis:\n"
                f"- Risk: {risk}\n"
                f"- Package: {package} {current_ver} → {fixed_version}\n"
                f"- PR: {pr_url}\n"
            )
            _jira_add_comment(ticket.key, comment)

        _jira_add_label(ticket.key, "cve-bot-processed")

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

    try:
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
    finally:
        cleanup_ocp_build_data_cache()

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
