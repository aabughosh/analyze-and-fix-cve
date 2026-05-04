# Analyze and Fix CVE

AI skill for Cursor and Claude Code that analyzes whether a Go repository is
affected by a specific CVE, and if affected, automatically applies the fix
and creates a pull request.

## What it does

Give it a CVE ID and a Go repo. It will:

1. **Look up the CVE** — find the affected package and fixed version
2. **Check your repo** — is the vulnerable package in `go.mod`?
3. **Run `govulncheck`** — does your code actually call the vulnerable functions?
4. **Report the risk** — HIGH (code calls vulnerable functions), LOW (dependency
   exists but not called), or NOT AFFECTED
5. **Apply the fix** — bump the dependency to the fixed version
6. **Run tests** — make sure nothing breaks
7. **Create a PR** — with full CVE details, analysis results, and test status

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
CVE-2026-34986
     │
     ▼
Look up CVE → affected package: go-jose, fixed: v4.1.4
     │
     ▼
Check go.mod → go-jose v4.0.2 (VULNERABLE)
     │
     ▼
Run govulncheck → Package Results only (LOW RISK)
     │
     ▼
Categorize → THIRD_PARTY → can auto-fix
     │
     ▼
go get github.com/go-jose/go-jose/v4@v4.1.4
go mod tidy
     │
     ▼
Run tests → all pass
     │
     ▼
Create PR → https://github.com/org/repo/pull/42
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

The bot runs as a GitHub Action on a schedule. It automatically:

1. Fetches new CVE tickets from Jira assigned to your team's components
2. Maps each ticket to a GitHub repo
3. Runs `govulncheck` to check if the code is affected
4. If affected, bumps the dependency and creates a PR
5. Posts the results back to the Jira ticket

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
