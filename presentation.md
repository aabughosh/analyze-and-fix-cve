# CVE Analyzer and Fixer — Presentation

Each section is one slide. Copy the **title** and **bullet points** into Google Slides. Speaker notes are in the blockquotes.

---

## Slide 1: Title

**CVE Analyzer and Fixer**

Automatically detect, fix, and create PRs for Go CVE vulnerabilities

Amal Abu Ghosh

> Speaker notes: I built a tool that takes a CVE ticket and does everything we normally do by hand — finds the repo, scans it, fixes the dependency, runs tests, and opens a PR. I'll walk you through what it does and show you a real example.

---

## Slide 2: What We Do Today (Manual)

**Every CVE ticket requires the same steps**

1. Read the Jira ticket, figure out which CVE and which repo
2. Clone the repo
3. Check if the vulnerable package is in go.mod
4. Run govulncheck to see if it's really affected
5. Find the fixed version
6. Bump the dependency, run go mod tidy
7. Run tests
8. Create a branch, push, open a PR
9. Go back to Jira, write a comment with the findings

**This takes 30–60 minutes per ticket.**

With 5–10 CVE tickets per sprint, that's **5–10 hours of repetitive work.**

> Speaker notes: Every single one of these steps is the same every time. It's not creative work — it's a checklist. And when you're doing 10 of them, it's easy to skip the Jira comment, miss a test, or forget to check if a PR already exists.

---

## Slide 3: What This Tool Does

**It does all of that automatically**

You give it a CVE → it gives you a PR

- Finds the right GitHub repo for the Jira ticket
- Scans the repo with govulncheck (the official Go vulnerability scanner)
- Tells you if the repo is actually affected or not
- If affected: bumps the dependency to the fixed version
- Runs tests to make sure nothing breaks
- Creates a pull request
- Comments on the Jira ticket with the full analysis

**~3 minutes instead of 30–60 minutes**

> Speaker notes: The key point is that it does the FULL pipeline — not just the scan. It scans, fixes, tests, creates the PR, and updates Jira. And if tests fail, it stops and tells you instead of pushing broken code.

---

## Slide 4: Two Ways to Use It

**Bot mode — fully automated**

- Runs as a GitHub Action every weekday at 8am
- Picks up all new CVE tickets from Jira for your team
- Processes them one by one, end to end
- No human needed

**Skill mode — interactive**

- Works inside Cursor or Claude Code (AI coding tools)
- You open a Go repo and ask: "Is this affected by CVE-2026-34986?"
- The AI follows the same steps and does everything in your editor

> Speaker notes: The bot handles batch processing — it watches your team's components and deals with new tickets automatically. The skill is for when you want to check something specific interactively, or for a repo that isn't covered by the bot.

---

## Slide 5: How It Decides If a Repo Is Affected

**govulncheck — the official Go vulnerability scanner**

- Not just "is the package in go.mod?" — that's too shallow
- govulncheck traces your code's call graph
- It checks: does your code actually **call** the vulnerable function?

**Three possible results:**

| Result | Meaning | What happens |
|--------|---------|--------------|
| **HIGH** | Your code calls the vulnerable function | Fix + PR created automatically |
| **LOW** | Package is a dependency but you don't call the vulnerable part | Recommended to fix |
| **NOT AFFECTED** | Package not in the repo or already on a safe version | Reported to Jira, done |

> Speaker notes: This is important because a lot of CVE scanners just check if the package is in your dependency tree. govulncheck goes deeper — it checks if your code actually reaches the vulnerable function. That means fewer false positives and more accurate risk assessments.

---

## Slide 6: What Happens When It Finds a Vulnerability

**Example: golang.org/x/net in cve-bot-test repo**

1. Jira ticket says: CVE-2026-4441 — vulnerability in `golang.org/x/net`
2. Tool clones the repo, finds `golang.org/x/net v0.23.0` in go.mod
3. Runs govulncheck → finds `main.go` calls `golang.org/x/net/html.Parse` → **HIGH risk**
4. Bumps `golang.org/x/net` from `v0.23.0` to `v0.33.0` (the fixed version)
5. Runs `go mod tidy`
6. Runs `go test ./...` → all tests pass
7. Creates PR: "Bump golang.org/x/net to v0.33.0 for CVE-2026-4441"
8. Comments on Jira with the full analysis

**Before:** 45 minutes of manual work. **After:** 3 minutes, no human involved.

> Speaker notes: This is a real example from our test repo. The tool found that main.go directly calls the vulnerable Parse function in golang.org/x/net/html, classified it as HIGH, bumped the dependency, ran tests, and created the PR — all automatically.

---

## Slide 7: What It Posts to Jira

**Every ticket gets a detailed comment**

For affected repos:
- Risk level (HIGH / LOW)
- Which package and which version
- What the fixed version is
- Link to the PR

For NOT AFFECTED repos:
- Evidence from govulncheck showing the repo is clean
- go.mod analysis showing the package isn't there (or is already fixed)

**No more "did you actually check this?" questions from the security team**

> Speaker notes: One of the biggest wins is consistency. Every single ticket gets the same level of detail in the Jira comment — the govulncheck output, the dependency analysis, the risk classification. The security team can see exactly what was checked and what was found.

---

## Slide 8: Safety — What Prevents Bad PRs

**Built-in guardrails**

- **Tests must pass** — if `go test` fails after the fix, the bot stops. No PR is created.
- **Duplicate detection** — checks if a PR already exists before creating a new one
- **Ticket tracking** — labels each ticket `cve-bot-processed` so it's never processed twice
- **Standard library handling** — if the vulnerability is in Go's stdlib (like `crypto/tls`), the bot can't fix it (needs a Go toolchain update). It reports this to Jira instead of silently skipping.

> Speaker notes: All of these were lessons from running an earlier version. The original didn't check for duplicates, didn't label tickets, and silently skipped stdlib vulns. Now every edge case is handled explicitly.

---

## Slide 9: Setup — What You Need

**Bot mode (3 secrets + 2 variables)**

| What | Where |
|------|-------|
| Jira URL, username, API token | GitHub Actions secrets |
| Your team's Jira components | GitHub Actions variable |
| Dry run on/off | GitHub Actions variable |

**Skill mode (just install the file)**

```
cp skill/SKILL.md ~/.cursor/skills/analyze-and-fix-cve/SKILL.md
```

Then open any Go repo and ask:
```
Check if this repo is affected by CVE-2026-34986
```

> Speaker notes: Setup takes about 5 minutes. For the bot, you add your Jira credentials as GitHub secrets and list your team's components. For the skill, you just copy one file. Both modes need Go installed and the gh CLI authenticated.

---

## Slide 10: Results

**What this saves**

| | Before | After |
|--|--------|-------|
| Time per CVE | 30–60 min | ~3 min |
| Jira comments | Sometimes skipped | Every ticket |
| Risk accuracy | Depends on who does it | Consistent (govulncheck) |
| Duplicate PRs | Happens on retries | Detected and skipped |
| Forgotten tickets | Happens | Impossible (label tracking) |

**10 tickets/sprint × 45 min = 7.5 hours saved per sprint**

> Speaker notes: The time saving is the obvious win, but consistency matters more. When every ticket gets the same analysis and the same Jira comment, the security team stops asking follow-up questions because the evidence is already there.

---

## Slide 11: Demo / Try It

**Try it yourself**

```bash
git clone https://github.com/amalabugosh/analyze-and-fix-cve.git
```

In Cursor or Claude Code, open a Go repo and ask:
```
Check if this repo is affected by CVE-2026-34986
```

**Links:**
- Repository: https://github.com/amalabugosh/analyze-and-fix-cve
- Related: [jira-cve-audit](https://github.com/amalabugosh/jira-cve-audit) — audit CVE ticket assignments

**Questions?**

> Speaker notes: If you have time for a live demo, open the cve-bot-test repo in Cursor and run the skill against a known CVE. The AI will walk through the full pipeline in real time.
