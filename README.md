# Analyze and Fix CVE

Automated CVE detection, analysis, fixing, and PR creation for Go repositories.
Works as a **GitHub Action bot** (runs on a schedule, no human needed) and as
an **AI skill** for Cursor/Claude Code (interactive use).

## What it does

Given a CVE and a Go repository, it performs the full analysis and fix pipeline:

1. **Find CVE tickets** — queries Jira for new unresolved CVE tickets assigned to your team
2. **Find the repo** — maps the Jira component to a GitHub repository automatically (via ocp-build-data, ticket summary, or pscomponent label)
3. **Check dependencies** — searches `go.mod` and `go.sum` for the vulnerable package
4. **Run `govulncheck`** — symbol-level analysis to determine if your code **actually calls** the vulnerable functions (not just whether the dependency exists)
5. **Classify the risk:**
   - **HIGH** — code calls vulnerable functions → fix immediately
   - **LOW** — dependency exists but vulnerable functions are not called → fix as best practice
   - **NOT AFFECTED** — package not in repo or already on a fixed version → no action needed
6. **Categorize the fix type:**
   - **THIRD_PARTY** (e.g. `github.com/go-jose/go-jose`) → auto-fix by bumping dependency
   - **EXTENDED_STDLIB** (e.g. `golang.org/x/net`) → auto-fix by bumping dependency
   - **STDLIB** (e.g. `crypto/tls`) → cannot auto-fix, requires Go toolchain update from another team
7. **Find the fixed version** — looks up the fix version from govulncheck output, the Go vulnerability database (vuln.go.dev), or the Go module proxy
8. **Apply the fix** — runs `go get package@fixed-version` and `go mod tidy` to bump the dependency
9. **Run tests** — runs `go test ./...` to make sure the fix does not break anything. If tests fail, the bot **stops and does not create a PR**
10. **Create a PR** — pushes a branch and opens a pull request with full CVE details, analysis evidence, and test results. For repos you do not own, it forks the repo first
11. **Post to Jira** — comments on the Jira ticket with a detailed analysis report including triple-verification evidence (govulncheck + dependency check + source code analysis)

## Quick start

### 1. Clone this repo

```bash
git clone https://github.com/amalabugosh/analyze-and-fix-cve.git
```

### 2. Install the skill

**Cursor:**

```bash
mkdir -p ~/.cursor/skills/analyze-and-fix-cve
cp analyze-and-fix-cve/skill/SKILL.md ~/.cursor/skills/analyze-and-fix-cve/SKILL.md
```

**Claude Code:**

```bash
ln -s /absolute/path/to/analyze-and-fix-cve/skill ~/.claude/skills/analyze-and-fix-cve
```

Replace `/absolute/path/to/` with the actual path on your machine.

### 3. Use it

Open any Go repository in your editor, then ask:

```
Check if this repo is affected by CVE-2026-34986
```

```
Analyze and fix CVE-2026-34986 and create a PR
```

```
Is ptp-operator vulnerable to CVE-2026-34986?
```

## Prerequisites

- **Go 1.20+** installed
- **`gh` CLI** installed and authenticated (`gh auth login`)
- The target repo must have a **`go.mod`** file (Go projects only)
- `govulncheck` is installed automatically if missing

## How it works

```
Jira ticket: OCPBUGS-84945 (CVE-2026-4441)
     │
     ▼
Find repo → extract "aabughosh/cve-bot-test" from ticket summary
     │
     ▼
Clone repo → fallback to main if release branch does not exist
     │
     ▼
Check go.mod → golang.org/x/net v0.23.0 (VULNERABLE)
     │
     ▼
Run govulncheck → Symbol Results: main.go calls html.Parse → HIGH RISK
     │
     ▼
Categorize → EXTENDED_STDLIB → can auto-fix
     │
     ▼
Find fixed version → govulncheck says v0.45.0
     │
     ▼
Apply fix → go get golang.org/x/net@v0.45.0 && go mod tidy
     │
     ▼
Run tests → go test ./... → all pass ✓
     │
     ▼
Create PR → https://github.com/aabughosh/cve-bot-test/pull/1
     │
     ▼
Comment on Jira → detailed analysis with triple-verification evidence
```

## Risk levels

| Level | What it means | Action |
|-------|---------------|--------|
| **HIGH** | Code calls vulnerable functions (`govulncheck` Symbol Results) | Fix immediately, PR created automatically |
| **LOW** | Dependency exists but not called (`govulncheck` Package Results) | Asks you — recommended to fix as best practice |
| **NOT AFFECTED** | Package not in repo or already fixed | Reports clean, stops |

## Fix types

| Type | Example | Can auto-fix? |
|------|---------|---------------|
| **THIRD_PARTY** | `github.com/go-jose/go-jose/v4` | Yes — bumps dependency |
| **EXTENDED_STDLIB** | `golang.org/x/crypto` | Yes — bumps dependency |
| **STDLIB** | `crypto/tls`, `net/http` | No — requires Go toolchain update, reports and stops |

## Bot mode (automated)

The bot runs as a GitHub Action on a schedule (every weekday at 8am UTC).
No human intervention needed. It handles everything end-to-end:

1. **Fetch new tickets** — queries Jira for unresolved CVE tickets assigned to your team's components
2. **Find the repo** — maps the Jira ticket to a GitHub repository using ocp-build-data, the ticket summary (`org/repo`), or the pscomponent label
3. **Clone and analyze** — clones the repo, runs `govulncheck ./...` for symbol-level vulnerability analysis
4. **Check dependencies** — verifies if the vulnerable package is in `go.mod`, `go.sum`, and source code (triple-verification)
5. **Classify risk** — HIGH (code calls vulnerable functions), LOW (dependency present but not called), or NOT AFFECTED
6. **Find fixed version** — looks up the fix version from govulncheck, vuln.go.dev, or proxy.golang.org
7. **Apply fix** — bumps the dependency (`go get package@fixed-version && go mod tidy`)
8. **Run tests** — runs `go test ./...` to verify the fix does not break anything. **If tests fail, the bot stops and does not create a PR**
9. **Create PR** — pushes a fix branch and opens a pull request with CVE details, analysis, and test results. For repos you do not own, it **forks the repo first** and creates the PR from your fork
10. **Post to Jira** — comments on the Jira ticket with a detailed analysis report and the PR link

If a CVE is **NOT AFFECTED**, the bot posts a detailed comment on Jira explaining why (with evidence) and moves on. No PR is created.

### Setup

1. Push this repo to GitHub
2. Go to **Settings → Secrets and variables → Actions**
3. Add these **secrets**:

   | Secret | Value |
   |--------|-------|
   | `JIRA_URL` | `https://redhat.atlassian.net` |
   | `JIRA_USERNAME` | Your Jira email |
   | `JIRA_API_TOKEN` | Your Jira API token |

4. Add these **variables** (Settings → Variables):

   | Variable | Value |
   |----------|-------|
   | `TEAM_COMPONENTS` | Comma-separated Jira components (e.g. `ptp,networking-ingress-commatrix,Storage`) |
   | `COMPONENT_MAP` | Optional manual mappings for components not in ocp-build-data (e.g. `networking-ingress-commatrix=https://github.com/openshift-kni/commatrix,ptp=https://github.com/openshift/ptp-operator`) |
   | `DRY_RUN` | `true` for testing, `false` for real PRs |

5. The bot runs **every weekday at 8am UTC**. You can also trigger it
   manually from **Actions → CVE Bot → Run workflow**.

### Run locally

```bash
export JIRA_URL="https://redhat.atlassian.net"
export JIRA_USERNAME="you@redhat.com"
export JIRA_API_TOKEN="your-token"
export GITHUB_TOKEN="your-github-token"
export TEAM_COMPONENTS="ptp,networking-ingress-commatrix"
export DRY_RUN="true"

pip install requests
python bot.py
```

Set `DRY_RUN=true` first to see what it would do without actually creating PRs.

## File structure

```
analyze-and-fix-cve/
  .github/workflows/
    cve-bot.yml       # GitHub Action — runs the bot on a schedule
  skill/
    SKILL.md          # Cursor/Claude skill for interactive use
  bot.py              # The bot script
  README.md           # This file
```

## Related tools

| Tool | Purpose |
|------|---------|
| [jira-cve-audit](https://github.com/amalabugosh/jira-cve-audit) | Check if CVE tickets in Jira are assigned to the correct team |
| [analyze-cve](https://gitlab.cee.redhat.com/sustaining-engineering/ocp-sustaining-tools/skills) | Symbol-level CVE analysis (sustaining-engineering) |
| [create-pr](https://gitlab.cee.redhat.com/sustaining-engineering/ocp-sustaining-tools/skills) | Automated PR creation with templates (sustaining-engineering) |
