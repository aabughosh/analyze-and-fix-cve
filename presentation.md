# Analyze and Fix CVE — Presentation

Each section below is one slide. Copy the **title** and **bullet points** into Google Slides. Speaker notes are in the blockquotes under each slide.

---

## Slide 1: Title

**Analyze and Fix CVE**

Automated CVE detection, fixing, and PR creation for Go repositories

Amal Abu Ghosh

> Speaker notes: This is a tool I built to automate the CVE triage and fix workflow for our Go repositories. It works in two modes — a fully automated bot and an interactive AI skill — and I'll walk you through both today.

---

## Slide 2: The Problem

**Manual CVE triage is slow and repetitive**

- A new OCPBUGS CVE ticket lands
- You read the ticket, figure out which repo it maps to
- Clone the repo, check go.mod for the vulnerable package
- Run govulncheck, interpret the output
- Find the fixed version, bump the dep, run go mod tidy
- Run tests, create a branch, push, open a PR
- Go back to Jira, write a comment with your findings
- **Per CVE: 30-60 minutes of manual work**
- Multiply by 5-10 tickets per sprint

> Speaker notes: Every one of these steps is something we do the same way every time. It's not creative work — it's a checklist. And when you have a batch of CVE tickets, it's easy to forget a step, skip the Jira comment, or make an inconsistent risk assessment. That's the gap this tool fills.

---

## Slide 3: The Solution

**One pipeline, two modes**

- **Bot mode** — GitHub Action, runs on a schedule (weekdays 8am UTC)
  - Zero-touch: fetches Jira tickets, analyzes, fixes, creates PRs, comments on Jira
  - No human needed unless tests fail or it's a STDLIB vuln

- **AI Skill mode** — Cursor / Claude Code
  - Interactive: you ask "Check if this repo is affected by CVE-2026-34986"
  - The AI follows the same pipeline, step by step, in your editor
  - Scanner-agnostic: works with whatever tools are on the machine

- **Same pipeline, same logic, different trigger**

> Speaker notes: The bot handles the batch processing — it picks up all new CVE tickets for our components and processes them end-to-end. The AI skill is for when you want to check a specific repo interactively, or when you're working on a repo that isn't covered by the bot's Jira query.

---

## Slide 4: Pipeline Overview

**End-to-end flow**

```
Jira ticket (OCPBUGS-XXXXX)
       |
       v
OSV API lookup (optional) --> get package + aliases + fixed version
       |                       if not found, continue anyway
       v
Find repo (ocp-build-data / summary / pscomponent)
       |
       v
Clone repo  -->  fallback to main if branch missing
       |
       v
govulncheck -json ./...
       |
       ├── Pass 1: match target CVE by ID/aliases --> found? use it
       |
       └── Pass 2: no match? extract package from ticket summary
           (e.g. "golang.org/x/net") and check if govulncheck
           found ANY vuln in that package --> found? use it
       |
       v
Classify: HIGH / LOW / NOT AFFECTED
       |
       v
Bump dependency + go mod tidy + go mod vendor
       |
       v
go test ./...  -->  tests fail? STOP, no PR
       |
       v
Check for duplicate PRs  -->  already exists? return URL
       |
       v
Create PR + comment on Jira + label cve-bot-processed
```

> Speaker notes: This is the full pipeline. The key design principle is "fail early, fail safe." The OSV lookup is optional — if the CVE isn't in OSV (e.g. it's brand new or an internal ID), the bot keeps going and relies on govulncheck. The two-pass detection ensures we catch vulnerabilities even when precise CVE matching fails. The test gate at the bottom ensures we never create a PR with broken code. And the label at the end prevents re-processing.

---

## Slide 5: OSV Pre-Validation (Optional)

**Enrich before you scan**

- First step: `GET https://api.osv.dev/v1/vulns/<CVE-ID>`
- **OSV** = Open Source Vulnerabilities — Google's database at [osv.dev](https://osv.dev) that aggregates known vulnerabilities across ecosystems including Go
- If the CVE is found, OSV returns:
  - Affected **Go package name** (e.g. `golang.org/x/net`)
  - **Fixed version** (e.g. `v0.33.0`)
  - **Go vulnerability ID** and aliases (e.g. `GO-2024-3333`)
- If the CVE is **not** found in OSV: the bot **continues anyway** and relies on govulncheck
- This is optional enrichment, not a hard gate
- Replaces a hardcoded keyword map we used before

**Why it matters:** gives the bot better context (exact package, fix version, aliases) when available, but never blocks the pipeline

> Speaker notes: Before this, we had a hardcoded dictionary mapping keywords like "grpc" to package names. It only covered about 12 packages. The OSV API covers the entire Go vulnerability database and gives us the exact package, fixed version, and aliases in one call. Importantly, if a CVE isn't in OSV — maybe it's brand new, or uses an internal ID — the bot doesn't stop. It proceeds to govulncheck which scans the repo directly. OSV is "nice to have" enrichment, not a gate.

---

## Slide 6: govulncheck JSON Mode + Two-Pass Detection

**Accurate per-CVE risk classification**

- Runs `govulncheck -json ./...` (not text mode)
- JSON output has structured entries per vulnerability:
  - `osv` entries with ID and aliases
  - `finding` entries with call traces
- **Two-pass detection:**
  - **Pass 1 (precise):** match the specific CVE by its ID and all known aliases from OSV
  - **Pass 2 (fallback):** if no precise match, extract the package name from the Jira ticket summary (e.g. `golang.org/x/net`) and check if govulncheck found ANY vulnerability in that package
- **Why JSON mode matters:**
  - Old text mode: checked if "Symbol Results" appeared *anywhere* in output
  - If CVE-A had symbol calls but CVE-B (our target) didn't, we'd misclassify CVE-B as HIGH
  - JSON mode: we check the specific finding for our CVE

> Speaker notes: This was actually a bug in the original version. The text output of govulncheck groups results into "Symbol Results" and "Package Results" sections, but it doesn't tell you which CVE is in which section without parsing the whole thing. With JSON mode, each finding is a separate object with its own OSV ID and trace data, so we can match exactly. The two-pass detection is critical for catching CVEs that aren't yet in public databases — if the ticket says "vulnerability in golang.org/x/net" and govulncheck found a known vulnerability in that package, the fallback match picks it up.

---

## Slide 7: Risk Classification and Fix Types

**Risk levels**

| Level | Meaning | Action |
|-------|---------|--------|
| **HIGH** | Code calls vulnerable functions (symbol trace found) | Fix immediately, PR created automatically |
| **LOW** | Dependency imported but vulnerable functions not called | Ask user / recommended fix as best practice |
| **NOT AFFECTED** | Package not in repo or already on fixed version | Report to Jira, stop |

**Fix types**

| Type | Example | Auto-fix? |
|------|---------|-----------|
| **THIRD_PARTY** | `github.com/go-jose/go-jose/v4` | Yes |
| **EXTENDED_STDLIB** | `golang.org/x/crypto` | Yes |
| **STDLIB** | `crypto/tls`, `net/http` | No — needs Go toolchain update |

> Speaker notes: The distinction between HIGH and LOW is important. HIGH means govulncheck found an actual call path from your code to the vulnerable function — that's a real risk. LOW means the package is in your dependency tree but you never call the vulnerable parts. We still recommend fixing LOW as best practice, but it's not urgent. STDLIB is the one we can't auto-fix — that requires the golang-builder team to update the Go toolchain.

---

## Slide 8: Safety Guardrails

**What prevents bad PRs and missed tickets**

- **Tests must pass** — `go test ./...` runs after every fix. If tests fail, the bot stops and does NOT create a PR
- **Duplicate PR detection** — checks `gh pr list --head <branch>` before creating. If a PR already exists, returns its URL instead
- **Ticket labeling** — adds `cve-bot-processed` label after every outcome (not just fixes). Prevents re-processing on the next run
- **STDLIB handling** — posts a Jira comment explaining Go toolchain update is needed, instead of silently skipping
- **Jira comment on every outcome** — NOT AFFECTED gets a detailed evidence comment too, not just fixes
- **HTTP retries** — all external calls (Jira, OSV, vuln.go.dev, proxy.golang.org) use retry with backoff

> Speaker notes: These were all lessons learned from running the earlier version. The original bot didn't label tickets, so it re-processed the same ones every run. It didn't check for duplicate PRs, so if Jira labeling failed, you'd get two identical PRs. And STDLIB vulnerabilities just got silently logged with no Jira comment, so the team had no visibility. All of that is fixed now.

---

## Slide 9: Bot Mode — GitHub Actions

**Fully automated, runs every weekday**

- Triggered by cron schedule (weekdays 8am UTC) or manual dispatch
- Fetches all unresolved CVE tickets for your team's components from Jira
- Filters out already-processed tickets (`cve-bot-processed` label)
- For each ticket:
  - OSV validate → find repo → clone → scan → classify → fix → test → PR → Jira
- **Performance optimizations:**
  - ocp-build-data cloned once per OCP version, shared across tickets in the batch
  - OSV pre-validation skips non-Go CVEs before cloning
- **Setup:** 3 secrets (Jira URL, user, token) + 2 variables (components, dry run)

> Speaker notes: The bot processes tickets sequentially — one at a time — to avoid overwhelming GitHub or Jira. The ocp-build-data caching was important because without it, a batch of 10 tickets on the same OCP version would clone the same 500MB repo 10 times. Now it clones once and reuses. You can always trigger it manually from the Actions tab if you don't want to wait for the next scheduled run.

---

## Slide 10: AI Skill Mode — Cursor / Claude Code

**Interactive CVE analysis in your editor**

- Install `SKILL.md` into Cursor or Claude Code
- Open any Go repo, then ask:
  - "Check if this repo is affected by CVE-2026-34986"
  - "Fix CVE-2026-34986 and create a PR"
- The AI follows the same 6-step pipeline:
  1. Gather inputs (CVE ID, repo, branch)
  2. Validate via OSV API
  3. Scan with govulncheck
  4. Report findings
  5. Classify and fix
  6. Create PR
- **Scanner-agnostic** — no hardcoded CLI commands. The AI adapts to whatever tools are available
- **Critical rule:** the scanner is the single source of truth. No manual grepping of go.mod

> Speaker notes: The skill is essentially a set of instructions for the AI, not a script. It tells the AI what steps to follow and what decisions to make, but it doesn't prescribe specific commands. That means it works in any environment — Cursor, Claude Code, different OS, whatever vulnerability scanner is installed. The "critical rule" about trusting the scanner was added based on reviewer feedback — it prevents the AI from second-guessing govulncheck with redundant go.mod grep checks.

---

## Slide 11: Impact

**What this saves us**

| | Manual | Automated |
|--|--------|-----------|
| **Time per CVE** | 30-60 min | ~3 min (bot) |
| **Jira evidence** | Inconsistent, sometimes skipped | Standardized, every ticket |
| **Forgotten tickets** | Happens | Impossible (label tracking) |
| **Duplicate PRs** | Possible on retries | Detected and skipped |
| **STDLIB visibility** | Often missed | Always reported to Jira |
| **Risk accuracy** | Depends on who triages | Per-CVE JSON-level analysis |

**Real numbers:**
- 10 CVE tickets per sprint x 45 min each = **7.5 hours saved per sprint**
- Consistent evidence on every ticket = fewer follow-up questions from security team

> Speaker notes: The time savings are the obvious win, but the consistency is arguably more important. When every ticket gets the same level of analysis — govulncheck, dependency check, source code check — and the same structured Jira comment, the security team stops asking "did you actually check this?" because the evidence is right there on the ticket.

---

## Slide 12: Demo / Questions

**Try it yourself**

```
git clone https://github.com/amalabugosh/analyze-and-fix-cve.git
```

In Cursor or Claude Code:
```
Check if this repo is affected by CVE-2026-34986
```

**Links:**
- Repository: https://github.com/amalabugosh/analyze-and-fix-cve
- Related: [jira-cve-audit](https://github.com/amalabugosh/jira-cve-audit) — audit CVE ticket assignments

**Questions?**

> Speaker notes: If you have time for a live demo, open a test Go repo in Cursor and run the skill against a known CVE. The AI will walk through the full pipeline in real time. Otherwise, the repo README has everything you need to set it up.
