---
name: analyze-and-fix-cve
description: >-
  Analyze whether a Go repository is affected by a CVE, and if affected,
  apply the fix and create a PR automatically. Use when the user asks to
  check a CVE against a repo, fix a CVE, or create a PR for a CVE fix.
---

# Analyze and Fix CVE

## CRITICAL RULE

During detection (Steps 2-3), rely **only** on the scanner and its database. Do not fetch CVE details from external sources (no cve.org, no NVD, no CVSS lookups). Do not manually grep `go.mod`, `go.sum`, or source files. Do not second-guess the scanner. The scanner is the single source of truth — if it does not report the CVE, the repo is not affected. Move on.

## Prerequisites

Go 1.20+, a way to create PRs on the hosting platform, repo has `go.mod`.

## 1. Gather inputs

Ask the user for anything missing:

1. **CVE ID** (e.g. `CVE-2026-34986`)
2. **Repository** — a remote URL or local path. Default to current working directory.
3. **Branch** — default to current branch

If the repository is a remote URL, clone it (with the target branch) into a temporary directory inside the current working directory (to satisfy sandbox restrictions). Delete this directory when done. If it's a local path, work in that directory directly. Confirm `go.mod` exists before proceeding.

## 2. Validate the CVE

Using only the scanner's own database:

1. Verify the CVE ID exists and is tracked. If not recognized -> report that the CVE is not in the database and stop.
2. Learn how the scanner identifies vulnerabilities in its output (it may use its own ID scheme, not CVE IDs). Note the scanner's ID for the target CVE.
3. Learn what fields the scanner reports so you know what to extract after scanning.

Do not look up CVE details from any other source during this step.

### If using govulncheck

To validate, HTTP GET `https://api.osv.dev/v1/vulns/<CVE-ID>`. A successful response confirms the CVE is tracked and returns the Go vulnerability ID (alias) and affected packages/versions.

## 3. Scan for the CVE

Scan the cloned repo for vulnerabilities and process the output with a simple filter to match the CVE ID or its aliases. The scanner should be configured to output all details to match on the CVE ID or its aliases. Also save the full output to a local file.
If there is no match, the repo is not affected. Report findings and stop.

### If using govulncheck

Use JSON output (-json) since it contains both CVE ID and its aliases.

## 4. Report findings

Summarize the full scanning file. First show the CVE that was matched. Then as extra data, list all other vulnerabilities found by CVE ID / Aliases.

- **NOT AFFECTED** -> stop
- **LOW** -> ask user whether to fix (recommended). If no, stop.
- **HIGH** -> proceed automatically

## 5. Classify and fix

Classify the package:

- No domain (`crypto/tls`, `net/http`) -> **STDLIB**: requires Go toolchain update, cannot auto-fix. Tell user to coordinate with `openshift-golang-builder-container` team. Stop.
- `golang.org/x/*` -> **EXTENDED_STDLIB**: fixable
- Other domain -> **THIRD_PARTY**: fixable

**5a.** Create a branch named `fix-cve-<CVE-ID>-<branch-name>`.

**5b.** Bump the dependency to the fixed version, tidy the module graph, and re-vendor if the repo uses vendoring.

**5c.** Run the project's tests. If tests fail, report failure and stop. Do NOT create a PR with failing tests.

**5d.** Check recent commit messages for `UPSTREAM:` prefix. If present, use commit format `UPSTREAM: <carry>: Bump <package> to v<fixed> for <CVE-ID>`. Otherwise use `<JIRA-ID>: Bump <package> to v<fixed> for <CVE-ID>`. Stage all changes and commit.

## 6. Create PR

Push the branch. Create a PR on the hosting platform. The PR body must include: CVE ID, package name, old version, fixed version, risk level, vulnerability scan result, what changed, test results, and links to cve.org and pkg.go.dev/vuln.

Report the PR URL to the user.

## Errors

- Vulnerability scanner not found -> install it
- CVE not in vulnerability database -> report invalid/unsupported CVE, stop
- CVE not found in scan results -> NOT AFFECTED, stop
- Dependency bump fails -> report error, ask user
- Tests fail -> report, do NOT create PR, ask user
- PR tool not authenticated -> ask user to authenticate
- No fixed version available -> report, stop
- STDLIB vulnerability -> report Go toolchain update needed, stop
