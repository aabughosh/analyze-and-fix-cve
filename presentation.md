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

## Slide 6: Three Types of Vulnerabilities

**Not all fixes are the same**

| Type | Examples | Can the tool fix it? |
|------|----------|---------------------|
| **THIRD_PARTY** | `github.com/go-jose/go-jose/v4` | Yes — bumps the dependency |
| **EXTENDED_STDLIB** | `golang.org/x/net`, `golang.org/x/crypto` | Yes — bumps the dependency |
| **STDLIB** | `crypto/tls`, `net/http` | No — requires upgrading Go itself |

**When it CAN fix (THIRD_PARTY / EXTENDED_STDLIB):**
- Looks up the fixed version, runs `go get package@fixed-version`, `go mod tidy`, tests, and creates a PR

**When it CAN'T auto-fix (STDLIB):**
- Packages like `crypto/tls` or `net/http` are part of the Go standard library — they're compiled into the Go binary
- You can't bump them with `go get` — the fix requires upgrading the Go version (e.g. `go 1.21.0` → `go 1.21.6` in go.mod)
- The tool doesn't do this automatically because a Go version upgrade can have broader impacts (new behavior, breaking changes)
- Instead, the tool **posts a Jira comment** with: risk level, which stdlib package is affected, and that a Go version upgrade is needed
- The repo owner can then decide when and how to upgrade

> Speaker notes: This distinction matters because a significant chunk of Go CVEs are in the standard library. When we see a stdlib vulnerability like crypto/tls or net/http, you can't just bump a dependency — you need to upgrade Go itself. That's a bigger change than bumping one package, so the tool doesn't do it automatically. But it still does the full analysis, tells you exactly what's affected, and posts it to Jira so it's not forgotten. Without the tool, stdlib CVEs often sit for weeks because people try to fix them like regular dependencies and can't figure out why it's not working.

---

## Slide 7: Real Example — What the Tool Actually Runs

**CVE-2026-4441 — golang.org/x/net in cve-bot-test repo**

**Step 1: Clone and check go.mod**
```
$ git clone https://github.com/aabughosh/cve-bot-test
$ cat go.mod
module github.com/aabughosh/cve-bot-test
go 1.24.10
require golang.org/x/net v0.23.0      <-- vulnerable version
```

**Step 2: Run govulncheck**
```
$ govulncheck -json ./...
```
Output (455K of JSON). The key part — a **finding with a symbol trace**:
```json
{
  "finding": {
    "osv": "GO-2024-3333",
    "fixed_version": "v0.33.0",
    "trace": [
      { "module": "golang.org/x/net", "function": "Parse" },
      { "module": "cve-bot-test",     "function": "main" }
    ]
  }
}
```
→ `main()` calls `html.Parse()` = your code calls the vulnerable function = **HIGH risk**
→ `fixed_version: v0.33.0` = that's the version we need to bump to

**Step 3: Fix**
```
$ go get golang.org/x/net@v0.33.0
$ go mod tidy
```

**Step 4: Test**
```
$ go test ./...
ok   github.com/aabughosh/cve-bot-test   0.003s
```

**Step 5: Create PR**
```
$ git push origin fix-cve-CVE-2026-4441
$ gh pr create --title "Bump golang.org/x/net to v0.33.0 for CVE-2026-4441"
```

> Speaker notes: This is a real example. The tool clones the repo, runs govulncheck in JSON mode, and parses the output. The finding tells us two things: first, it has a function in the trace — meaning our code actually calls the vulnerable function, so it's HIGH risk. Second, the fixed_version field tells us exactly which version to bump to. Then it's just go get, go mod tidy, run tests, and create a PR. The whole thing takes about 3 minutes.

---

## Slide 8: Example — STDLIB Vulnerability (Can't Auto-Fix)

**What happens when bumping a dependency isn't enough?**

Example: CVE in `crypto/tls` (part of Go's standard library)

1. Tool clones the repo, runs govulncheck → detects the vulnerability
2. Classifies the package: `crypto/tls` has no domain → **STDLIB**
3. The tool **cannot fix this** — `crypto/tls` is compiled into the Go binary, not a go.mod dependency
4. Instead, the tool posts a Jira comment:
   - Risk level: HIGH
   - Package: `crypto/tls`
   - "This is a standard library vulnerability — requires upgrading the Go version"
   - "Cannot be fixed by bumping a dependency"
5. Labels the ticket `cve-bot-processed`

**The tool doesn't silently skip it — it does the analysis, explains the problem, and makes it visible so the repo owner can act on it.**

> Speaker notes: This is an important case because without the tool, stdlib CVEs often just sit there. People try to fix them like a regular dependency bump, can't find the package in go.mod, and give up. Or they don't realize the CVE is in the standard library at all. The tool catches this immediately — it tells you it's a stdlib issue, which package is affected, and that the fix is to upgrade Go. The repo owner can then plan the Go upgrade knowing exactly which CVEs it will resolve.

---

## Slide 9: What It Posts to Jira

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

## Slide 10: Safety — What Prevents Bad PRs

**Built-in guardrails**

- **Tests must pass** — if `go test` fails after the fix, the bot stops. No PR is created.
- **Duplicate detection** — checks if a PR already exists before creating a new one
- **Ticket tracking** — labels each ticket `cve-bot-processed` so it's never processed twice
- **Standard library handling** — if the vulnerability is in Go's stdlib (like `crypto/tls`), the bot can't bump a dependency. It reports to Jira that a Go version upgrade is needed instead of silently skipping.

> Speaker notes: All of these were lessons from running an earlier version. The original didn't check for duplicates, didn't label tickets, and silently skipped stdlib vulns. Now every edge case is handled explicitly.

---

## Slide 11: Setup — What You Need

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

## Slide 12: Results

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

## Slide 13: How Much Does It Cost to Run?

**GitHub Actions pricing (Linux runner)**

| | |
|--|--|
| Per-minute rate | **$0.006** (Linux 2-core) |
| Public repos | **Free** (always) |
| Free plan (private repos) | **2,000 minutes/month included** |
| Enterprise plan | **50,000 minutes/month included** |

**What the bot actually uses:**

Based on real runs:
- Processing one ticket (clone + scan + fix + test + PR): **~30 seconds**
- A typical run with 5 tickets: **~3 minutes** (including setup)
- Runs once per weekday: **~22 runs/month**

| Scenario | Minutes/month | Cost |
|----------|--------------|------|
| 5 tickets/run | ~66 min | **Free** (well within free tier) |
| 10 tickets/run | ~110 min | **Free** (well within free tier) |
| 20 tickets/run | ~200 min | **Free** (well within free tier) |
| 50 tickets/run (heavy) | ~500 min | **Free** or ~$3/month if over quota |

**Bottom line: it's essentially free.** Even with 20 tickets per run, you'd use ~200 minutes/month out of 2,000 free minutes. That's 10% of the free quota.

> Speaker notes: This is a common question. GitHub Actions is free for public repos. For private repos, every plan includes free minutes — 2,000 on the free plan, 50,000 on Enterprise. Our bot uses about 30 seconds per ticket, so even processing 20 tickets every weekday uses only 200 minutes per month — 10% of the free tier. The Linux runner costs $0.006 per minute if you go over, so even in the worst case you're looking at a few dollars per month. Compare that to 7.5 hours of engineer time per sprint.

---

## Slide 14: Demo / Try It

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
