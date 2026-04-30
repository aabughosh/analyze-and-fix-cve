---
name: analyze-and-fix-cve
description: >-
  Analyze whether a Go repository is affected by a CVE, and if affected,
  apply the fix and create a PR automatically. Use when the user asks to
  check a CVE against a repo, fix a CVE, or create a PR for a CVE fix.
---

# Analyze and Fix CVE

Determine if a Go repository is affected by a specific CVE. If affected,
apply the dependency fix and create a pull request automatically.

## Trigger phrases

- "Check if this repo is affected by CVE-XXXX"
- "Analyze and fix CVE-XXXX in this repo"
- "Is ptp-operator vulnerable to CVE-XXXX?"
- "Fix CVE-XXXX and open a PR"

## Prerequisites

- Go 1.20+ installed
- `gh` CLI installed and authenticated (`gh auth login`)
- The repo must have a `go.mod` file (Go projects only)

## Step 1: Gather information

Ask the user for any missing details:

1. **CVE ID** — e.g. `CVE-2026-34986`
2. **Repository** — use the current working directory if not specified
3. **Branch** — use the current branch if not specified, or ask which
   release branch (e.g. `release-4.21`)

## Step 2: Look up the CVE

Search for CVE details to identify the affected package and fixed version.

```bash
# Check the Go vulnerability database
go install golang.org/x/vuln/cmd/govulncheck@latest 2>/dev/null
govulncheck -json ./... 2>/dev/null | head -100
```

If the CVE ID is known, also check:
- `https://pkg.go.dev/vuln/{CVE-ID}`
- `https://www.cve.org/CVERecord?id={CVE-ID}`

Extract:
- **Affected package** (e.g. `github.com/go-jose/go-jose/v4`)
- **Vulnerable versions** (e.g. `< 4.1.4`)
- **Fixed version** (e.g. `4.1.4`)

## Step 3: Check if the repo is affected

### 3a. Check if the package is in go.mod

```bash
grep "<package-name>" go.mod
```

If not found → **NOT AFFECTED**. Report to the user and stop.

### 3b. Check the version

Compare the version in `go.mod` against the vulnerable range.

- If already on the fixed version or newer → **NOT AFFECTED**. Report and stop.
- If on a vulnerable version → continue to Step 3c.

### 3c. Run govulncheck for symbol-level analysis

```bash
govulncheck ./...
```

Interpret the results:

| govulncheck output | Risk level | Meaning |
|--------------------|------------|---------|
| Listed in **Symbol Results** with call traces | **HIGH RISK** | Code CALLS the vulnerable functions |
| Listed in **Package Results** only | **LOW RISK** | Dependency exists but vulnerable functions are not called |
| No results | **NOT AFFECTED** | Not vulnerable |

### 3d. Check the dependency chain

```bash
go mod why <package-name>
```

This shows how the dependency is pulled in (direct vs transitive).

## Step 4: Report findings

Present a clear summary to the user:

```
## CVE Analysis Report

**CVE:** CVE-XXXX-XXXXX
**Package:** <package-name>
**Current version:** vX.Y.Z (VULNERABLE)
**Fixed version:** vA.B.C
**Risk level:** HIGH / LOW / NOT AFFECTED

**govulncheck:** Symbol Results found / Package Results only / Clean
**Dependency chain:** Direct / Transitive via <parent-package>

**Recommendation:** Update immediately / Update as best practice / No action needed
```

If **NOT AFFECTED** → stop here.

If **LOW RISK** → ask the user if they want to fix it anyway (recommended as
best practice). If they say no, stop here.

If **HIGH RISK** → proceed to Step 5 automatically.

## Step 5: Categorize the fix type

Determine what kind of fix is needed:

| Package path pattern | Type | Fix method |
|---------------------|------|------------|
| No domain (e.g. `crypto/tls`, `net/http`) | **STDLIB** | Go toolchain update needed — CANNOT auto-fix. Tell the user they need to coordinate with the `openshift-golang-builder-container` team. Stop here. |
| `golang.org/x/*` | **EXTENDED_STDLIB** | `go get golang.org/x/<pkg>@<fixed-version>` |
| `github.com/...` or other domain | **THIRD_PARTY** | `go get <package>@<fixed-version>` |

If **STDLIB** → report that this requires a Go toolchain update and stop.
The user cannot fix this with a dependency bump.

## Step 6: Apply the fix

### 6a. Create a fix branch

```bash
git checkout -b fix-cve-<CVE-ID>-<branch-name>
```

### 6b. Bump the dependency

```bash
go get <package>@v<fixed-version>
go mod tidy
```

If the repo uses vendoring:

```bash
go mod vendor
```

### 6c. Verify the fix

```bash
# Confirm the version is updated
grep "<package-name>" go.mod

# Re-run govulncheck to confirm the vulnerability is resolved
govulncheck ./...

# Run tests
go test ./...
```

If tests fail, report the failure to the user and ask how to proceed.
Do NOT create a PR with failing tests.

### 6d. Commit the changes

Determine the correct commit message format.

Check if this is a vendored upstream repo by looking for `UPSTREAM` in
recent commit messages:

```bash
git log --oneline -20 | head -5
```

If recent commits use `UPSTREAM:` prefix:

```bash
git add -A
git commit -m "UPSTREAM: <carry>: Bump <package> to v<fixed> for <CVE-ID>"
```

Otherwise use a standard format:

```bash
git add -A
git commit -m "<JIRA-ID>: Bump <package> to v<fixed> for <CVE-ID>"
```

## Step 7: Create the pull request

```bash
git push origin fix-cve-<CVE-ID>-<branch-name>

gh pr create \
  --title "<JIRA-ID>: Bump <package> to v<fixed> for <CVE-ID>" \
  --body "$(cat <<'EOF'
## CVE Fix

**CVE:** <CVE-ID>
**Package:** <package-name>
**Previous version:** v<old-version> (vulnerable)
**Fixed version:** v<fixed-version>

## Analysis

- **govulncheck result:** <Symbol Results / Package Results>
- **Risk level:** <HIGH / LOW>
- **Dependency type:** <Direct / Transitive>

## Changes

- Updated `<package>` from `v<old>` to `v<fixed>` in `go.mod`
- Ran `go mod tidy` to update `go.sum`

## Testing

- [x] `govulncheck ./...` — clean (no vulnerability found)
- [x] `go test ./...` — all tests pass

## References

- https://www.cve.org/CVERecord?id=<CVE-ID>
- https://pkg.go.dev/vuln/<CVE-ID>
EOF
)"
```

Report the PR URL to the user.

## Step 8: Summary

After completing all steps, present a final summary:

```
## Done!

**CVE:** CVE-XXXX-XXXXX
**Risk:** HIGH / LOW
**Fix:** Bumped <package> from v<old> to v<fixed>
**PR:** <URL>
**Tests:** All passing

Next steps:
- Review the PR
- Merge when approved
- Update the Jira ticket (if applicable)
```

## Error handling

| Error | What to do |
|-------|------------|
| `govulncheck` not found | Run `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| Package not in `go.mod` | Report NOT AFFECTED and stop |
| `go get` fails | Report the error and ask the user for help |
| Tests fail after fix | Report failures, do NOT create PR, ask user |
| `gh` not authenticated | Ask user to run `gh auth login` |
| No fixed version available | Report that no fix exists yet and stop |
| STDLIB vulnerability | Report that Go toolchain update is needed, stop |
