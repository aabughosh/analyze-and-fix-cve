# Analyze and Fix CVE

Automated CVE detection, analysis, fixing, and PR creation for Go repositories.
Works as a **GitHub Action bot** (runs on a schedule, no human needed) and as
an **AI skill** for Cursor/Claude Code (interactive use).

## What it does

Given a CVE and a Go repository, it performs the full analysis and fix pipeline:

1. **Validate the CVE** — calls the OSV API to confirm the CVE is tracked in the Go vulnerability database and retrieves the affected package, aliases, and fixed version upfront
2. **Find CVE tickets** (bot mode) — queries Jira for new unresolved CVE tickets assigned to your team
3. **Find the repo** — maps the Jira component to a GitHub repository automatically (via ocp-build-data, ticket summary, or pscomponent label)
4. **Run `govulncheck -json`** — symbol-level analysis in JSON mode, matching the specific CVE by its OSV aliases to determine if your code **actually calls** the vulnerable functions
5. **Classify the risk:**
   - **HIGH** — code calls vulnerable functions → fix immediately
   - **LOW** — dependency exists but vulnerable functions are not called → fix as best practice
   - **NOT AFFECTED** — package not in repo or already on a fixed version → no action needed
6. **Categorize the fix type:**
   - **THIRD_PARTY** (e.g. `github.com/go-jose/go-jose`) → auto-fix by bumping dependency
   - **EXTENDED_STDLIB** (e.g. `golang.org/x/net`) → auto-fix by bumping dependency
   - **STDLIB** (e.g. `crypto/tls`) → cannot auto-fix, requires Go toolchain update from another team
7. **Apply the fix** — runs `go get package@fixed-version` and `go mod tidy` to bump the dependency
8. **Run tests** — runs `go test ./...` to make sure the fix does not break anything. If tests fail, the bot **stops and does not create a PR**
9. **Create a PR** — checks for existing PRs to avoid duplicates, then pushes a branch and opens a pull request. For repos you do not own, it forks the repo first
10. **Post to Jira** — comments on the Jira ticket with a detailed analysis report and labels the ticket `cve-bot-processed` to prevent re-processing

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
- A way to create PRs on the hosting platform (e.g. `gh` CLI authenticated)
- The target repo must have a **`go.mod`** file (Go projects only)
- `govulncheck` is installed automatically if missing

## How it works

```
CVE-2026-4441
     │
     ▼
Validate via OSV API → confirms CVE exists, gets package + aliases + fixed version
     │
     ▼
Find repo → ocp-build-data / ticket summary / pscomponent label
     │
     ▼
Clone repo → fallback to main if release branch does not exist
     │
     ▼
Run govulncheck -json → match target CVE by aliases → HIGH RISK (symbol call found)
     │
     ▼
Categorize → EXTENDED_STDLIB → can auto-fix
     │
     ▼
Apply fix → go get golang.org/x/net@v0.45.0 && go mod tidy
     │
     ▼
Run tests → go test ./... → all pass ✓
     │
     ▼
Check for duplicate PRs → none found → create PR
     │
     ▼
Comment on Jira + label cve-bot-processed
```

## Risk levels

| Level | What it means | Action |
|-------|---------------|--------|
| **HIGH** | Code calls vulnerable functions (govulncheck symbol trace) | Fix immediately, PR created automatically |
| **LOW** | Dependency exists but not called (govulncheck finding without symbol trace) | Asks you — recommended to fix as best practice |
| **NOT AFFECTED** | Package not in repo or already fixed | Reports clean, stops |

## Fix types

| Type | Example | Can auto-fix? |
|------|---------|---------------|
| **THIRD_PARTY** | `github.com/go-jose/go-jose/v4` | Yes — bumps dependency |
| **EXTENDED_STDLIB** | `golang.org/x/crypto` | Yes — bumps dependency |
| **STDLIB** | `crypto/tls`, `net/http` | No — requires Go toolchain update, reports to Jira and stops |

## Bot mode (automated)

The bot runs as a GitHub Action on a schedule (every weekday at 8am UTC).
No human intervention needed. It handles everything end-to-end:

1. **Fetch new tickets** — queries Jira for unresolved CVE tickets assigned to your team's components (skips tickets already labeled `cve-bot-processed`)
2. **Pre-validate via OSV** — calls `api.osv.dev` to confirm the CVE is tracked, get the affected Go package, fixed version, and vulnerability aliases. Skips early if the CVE is not in the database
3. **Find the repo** — maps the Jira ticket to a GitHub repository using ocp-build-data (cached per OCP version), the ticket summary (`org/repo`), or the pscomponent label
4. **Clone and analyze** — clones the repo, runs `govulncheck -json ./...` and matches findings to the target CVE by its aliases for accurate per-CVE risk classification
5. **Classify risk** — HIGH (code calls vulnerable functions), LOW (dependency present but not called), or NOT AFFECTED
6. **Apply fix** — bumps the dependency (`go get package@fixed-version && go mod tidy`)
7. **Run tests** — runs `go test ./...` to verify the fix does not break anything. **If tests fail, the bot stops and does not create a PR**
8. **Create PR** — checks for existing PRs to avoid duplicates, then pushes a fix branch and opens a pull request. For repos you do not own, it **forks the repo first**
9. **Post to Jira** — comments on the Jira ticket with a detailed analysis report and labels the ticket `cve-bot-processed`

If a CVE is **NOT AFFECTED**, the bot posts a detailed comment on Jira explaining why (with evidence), labels the ticket, and moves on. No PR is created.

If a CVE is **STDLIB**, the bot posts a comment explaining that a Go toolchain update is needed and labels the ticket. No PR is created.

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
