# CVE Analyzer and Fixer for Go

An automated tool that detects whether a Go repository is vulnerable to a specific CVE, applies the fix, runs tests, and creates a pull request. No manual work required.

It works in two modes:
- **Bot mode** — runs as a GitHub Action on a schedule. Watches your team's Jira tickets and handles them automatically.
- **Skill mode** — an interactive AI skill for Cursor or Claude Code. You ask it to check a CVE and it does everything for you.

## How it works (step by step)

```
┌──────────────────────────────────────────────────────┐
│  1. INPUT                                            │
│     CVE ID (e.g. CVE-2026-34986)                     │
│     + Go repository                                  │
└──────────────────┬───────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────┐
│  2. PRE-VALIDATE (optional)                          │
│     Query the OSV database to learn which Go         │
│     package is affected and what version fixes it.   │
│     If OSV doesn't have this CVE, keep going —       │
│     govulncheck will still scan for it.              │
└──────────────────┬───────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────┐
│  3. SCAN                                             │
│     Run govulncheck -json on the repository.         │
│     This does symbol-level analysis: it checks       │
│     whether your code actually CALLS any vulnerable  │
│     functions, not just whether the package is in     │
│     go.mod.                                          │
│                                                      │
│     Two-pass detection:                              │
│     • Pass 1: Look for this exact CVE by its ID      │
│     • Pass 2: If not found, extract the package      │
│       name from the ticket (e.g. golang.org/x/net)   │
│       and check if govulncheck found ANY             │
│       vulnerability in that package                  │
└──────────────────┬───────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────┐
│  4. CLASSIFY                                         │
│     HIGH  — your code calls vulnerable functions     │
│     LOW   — package is a dependency but not called   │
│     NOT AFFECTED — package not present or already    │
│                    on a fixed version                 │
└──────────────────┬───────────────────────────────────┘
                   │
          ┌────────┴────────┐
          │                 │
     NOT AFFECTED       HIGH or LOW
          │                 │
          ▼                 ▼
┌─────────────────┐ ┌──────────────────────────────────┐
│ Report clean.   │ │  5. FIX                          │
│ Comment on Jira.│ │     Bump the dependency to the   │
│ Stop.           │ │     fixed version, run go mod    │
└─────────────────┘ │     tidy, re-vendor if needed.   │
                    └──────────────┬────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────────┐
                    │  6. TEST                         │
                    │     Run go test ./...            │
                    │     If tests FAIL → stop.        │
                    │     No PR is created.            │
                    └──────────────┬────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────────┐
                    │  7. CREATE PR                    │
                    │     Check for duplicate PRs.     │
                    │     Push fix branch.             │
                    │     Open pull request.           │
                    │     Comment on Jira ticket.      │
                    └──────────────────────────────────┘
```

## Key concepts

### What is OSV?

**OSV** (Open Source Vulnerabilities) is a vulnerability database run by Google at [osv.dev](https://osv.dev). It aggregates known vulnerabilities across open-source ecosystems including Go, Python, Rust, npm, and more.

The Go vulnerability database at [vuln.go.dev](https://vuln.go.dev) is part of OSV. Each vulnerability gets a Go ID (like `GO-2024-3333`) which maps to one or more CVE IDs (like `CVE-2024-45338`).

This tool uses the OSV API (`https://api.osv.dev/v1/vulns/<CVE-ID>`) as an **optional** first step to quickly look up:
- Whether the CVE exists in the Go vulnerability database
- Which Go package is affected (e.g. `golang.org/x/net`)
- What version fixes it (e.g. `v0.33.0`)
- The Go vulnerability ID and aliases

If OSV doesn't have the CVE (e.g. it's brand new or an internal ID), the tool continues anyway and relies on `govulncheck` to detect it.

### What is govulncheck?

**govulncheck** is the official Go vulnerability scanner from the Go team. Unlike basic dependency scanners that just check `go.mod`, govulncheck does **symbol-level analysis** — it traces your code's call graph to determine whether vulnerable functions are actually called.

This means:
- If your `go.mod` lists a vulnerable package but your code never calls the vulnerable function → `LOW` risk (not `HIGH`)
- If your code directly calls the vulnerable function → `HIGH` risk
- If the vulnerable package isn't in your dependencies at all → `NOT AFFECTED`

### Two-pass detection

Some CVEs are too new to be in any database, or use internal IDs that don't match public databases. The tool handles this with two-pass detection:

1. **Pass 1 (precise):** Match the specific CVE by its ID and all known aliases from the OSV database
2. **Pass 2 (fallback):** If Pass 1 finds nothing, extract the package name from the Jira ticket summary (e.g. "golang.org/x/net" from "Infinite parsing loop in golang.org/x/net") and check if govulncheck found ANY vulnerability in that package

This ensures that even CVEs that aren't indexed yet are caught if the package itself has known vulnerabilities.

### Risk levels

| Level | Meaning | What happens |
|-------|---------|--------------|
| **HIGH** | Your code calls vulnerable functions | Fix is applied and PR is created automatically |
| **LOW** | The vulnerable package is a dependency but the vulnerable functions are not called | You're asked whether to fix (recommended) |
| **NOT AFFECTED** | The package is not in the repo, or the repo is already on a safe version | Reported as clean, no action taken |

### Fix types

| Type | Example packages | Can auto-fix? |
|------|-----------------|---------------|
| **THIRD_PARTY** | `github.com/go-jose/go-jose/v4` | Yes — bumps the dependency |
| **EXTENDED_STDLIB** | `golang.org/x/net`, `golang.org/x/crypto` | Yes — bumps the dependency |
| **STDLIB** | `crypto/tls`, `net/http` | No — these are part of the Go standard library. Fixing them requires upgrading the Go version in go.mod, not bumping a dependency. The bot reports this to Jira and stops. |

## Quick start

### Skill mode (interactive)

Use this when you want to manually check a CVE against a specific repo.

**1. Clone this repo:**

```bash
git clone https://github.com/amalabugosh/analyze-and-fix-cve.git
```

**2. Install the skill:**

For Cursor:
```bash
mkdir -p ~/.cursor/skills/analyze-and-fix-cve
cp analyze-and-fix-cve/skill/SKILL.md ~/.cursor/skills/analyze-and-fix-cve/SKILL.md
```

For Claude Code:
```bash
ln -s /absolute/path/to/analyze-and-fix-cve/skill ~/.claude/skills/analyze-and-fix-cve
```

**3. Use it:**

Open any Go repository in your editor and ask:

```
Check if this repo is affected by CVE-2026-34986
```

```
Analyze and fix CVE-2026-34986 and create a PR
```

```
Is ptp-operator vulnerable to CVE-2026-34986?
```

### Bot mode (automated)

Use this when you want the tool to run automatically and handle your team's CVE tickets without human intervention.

**1. Push this repo to GitHub**

**2. Add secrets** (Settings → Secrets and variables → Actions):

| Secret | What it is |
|--------|------------|
| `JIRA_URL` | Your Jira instance URL (e.g. `https://redhat.atlassian.net`) |
| `JIRA_USERNAME` | Your Jira email address |
| `JIRA_API_TOKEN` | Your Jira API token ([create one here](https://id.atlassian.com/manage/api-tokens)) |

**3. Add variables** (Settings → Variables):

| Variable | What it is | Example |
|----------|------------|---------|
| `TEAM_COMPONENTS` | Comma-separated list of your team's Jira components | `ptp,networking-ingress-commatrix` |
| `COMPONENT_MAP` | Manual repo mappings for components not in ocp-build-data | `networking-ingress-commatrix=https://github.com/openshift-kni/commatrix` |
| `DRY_RUN` | Set to `true` for testing (no PRs created), `false` for production | `true` |

**4. Run it:**

The bot runs automatically **every weekday at 8am UTC**. You can also trigger it manually from **Actions → CVE Bot → Run workflow**.

**Run locally for testing:**

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

## What the bot does for each ticket

1. **Fetches new CVE tickets** from Jira — filters for unresolved SecurityTracking tickets in your team's components, skipping any already labeled `cve-bot-processed`
2. **Looks up the CVE in OSV** — gets the affected package, fixed version, and aliases. If the CVE isn't in OSV, it continues anyway
3. **Finds the GitHub repo** — uses ocp-build-data mappings, the ticket summary, or the component map you configured
4. **Clones the repo** — tries the release branch first, falls back to main/master if it doesn't exist
5. **Runs govulncheck -json** — scans for vulnerabilities with two-pass detection (precise match, then fallback)
6. **Classifies risk** — HIGH, LOW, or NOT AFFECTED based on symbol-level analysis
7. **Applies the fix** — bumps the dependency to the fixed version, runs `go mod tidy`
8. **Runs tests** — `go test ./...`. If tests fail, stops immediately without creating a PR
9. **Creates a PR** — checks for duplicates first, forks if needed, pushes a fix branch and opens the PR
10. **Updates Jira** — posts a detailed analysis comment and adds the `cve-bot-processed` label

For **NOT AFFECTED** tickets: posts a Jira comment with evidence (govulncheck output, go.mod analysis) and labels the ticket. No PR created.

For **STDLIB** vulnerabilities: posts a Jira comment explaining that the vulnerability is in the Go standard library and requires a Go version upgrade. No PR created.

## Prerequisites

- **Go 1.20+** installed
- A way to create PRs (e.g. `gh` CLI authenticated, or `GITHUB_TOKEN` set)
- The target repo must have a `go.mod` file (this tool is for Go projects only)
- `govulncheck` is installed automatically if it's missing

## File structure

```
analyze-and-fix-cve/
├── .github/workflows/
│   └── cve-bot.yml       # GitHub Action — runs the bot on a schedule
├── skill/
│   └── SKILL.md          # AI skill for Cursor / Claude Code (interactive)
├── bot.py                # The bot script (automated)
├── presentation.md       # Presentation outline
└── README.md             # This file
```

## Related tools

| Tool | Purpose |
|------|---------|
| [jira-cve-audit](https://github.com/amalabugosh/jira-cve-audit) | Check if CVE tickets in Jira are assigned to the correct team |
| [analyze-cve](https://gitlab.cee.redhat.com/sustaining-engineering/ocp-sustaining-tools/skills) | Symbol-level CVE analysis (sustaining-engineering) |
| [create-pr](https://gitlab.cee.redhat.com/sustaining-engineering/ocp-sustaining-tools/skills) | Automated PR creation with templates (sustaining-engineering) |
