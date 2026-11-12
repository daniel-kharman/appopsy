---
name: ship
description: Ship the current change as a pull request. Branch, run tests, lint, types and both third-party checks, run the relevant reviewers (privacy-reviewer always, report-reader if report output changed, allowlist-guard if adb.py, collectors, .claude, .githooks or .github changed), fix what they find, then open a PR whose description lists their findings and fixes. Never merges.
argument-hint: "[short description of the change]"
model: sonnet
allowed-tools:
  - Bash(uv run appopsy redact-fixture --check *)
  - Bash(uv run appopsy mask *)
  - Bash(uv run python scripts/make_sample_report.py)
---

# /ship

Turn the work in progress into a reviewed pull request. You may do every step
here without asking (CLAUDE.md, Autonomy), **except**: if the change adds or
changes an adb allowlist entry, contains a fixture from a real phone that the
maintainer hasn't approved, changes `.claude/settings.json` permissions, or
would change repo settings or publish anything, stop and ask first. Never
merge, never push to `main`, never force-push, never use `--no-verify`.

## 1. Branch

- If on `main`, create a branch: `git switch -c <kebab-case-summary>`.
- If on a branch whose PR is already merged or whose upstream is gone
  (`git status -sb` shows `[gone]`), branch again from `origin/main` and carry
  the work over; don't reuse it.
- Commit in small, reviewable commits (one collector/parser/rule at a time).
  Every message ends with the `Co-Authored-By:` trailer from your
  instructions. The pre-commit hook runs on each commit; if it fails, fix the
  cause, never bypass it.

## 2. Checks (all must pass)

```
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest -q
uv run appopsy redact-fixture --check --third-party-list ~/.config/appopsy/my-apps.txt tests/fixtures 2>&1 | uv run appopsy mask
uv run appopsy redact-fixture --check --apps-only --third-party-list ~/.config/appopsy/my-apps.txt . 2>&1 | uv run appopsy mask
```

Fix failures and rerun. If report output changed and the sample-report test
fails as stale, regenerate it with `uv run python scripts/make_sample_report.py`
and commit the result.

## 3. Pick reviewers from the changed paths

`git diff --name-only origin/main...HEAD` (plus anything uncommitted):

| Reviewer | When |
| --- | --- |
| `privacy-reviewer` | always |
| `report-reader` | `appopsy/report/`, `appopsy/rules/` (code or specs), `docs/sample-report.*` changed, or anything else that changes report text |
| `allowlist-guard` | `appopsy/adb.py`, `appopsy/collectors/`, `.claude/`, `.githooks/` or `.github/` changed |

Run the selected agents **in parallel** (one message, several Agent calls),
each with an explicit scope: the diff range `origin/main...HEAD`, the list of
changed files, and for report-reader the report file(s) to read (default
`docs/sample-report.md`). Give them the code, not your conclusions.

## 4. Fix, then re-check

- Fix every finding you can (blockers and should-fix first). Commit the fixes
  separately ("Review fixes: …") so the PR shows what changed.
- If you changed anything, rerun step 2 and rerun only the reviewers whose
  paths your fixes touched, once.
- A finding you can't or shouldn't resolve (needs the maintainer's decision, is
  out of scope, or you disagree) is **not hidden**: it goes into the PR under
  "Open items", with your reasoning.
- An allowlist change, or any finding that says "needs maintainer approval",
  goes at the top of the PR description.

## 5. Push and open the PR

```
git push -u origin <branch>
```

Run it as a single command (no `cd …&&`, no pipe): only then does it run
outside the sandbox, which it needs to reach GitHub. The same goes for
`gh pr create` below. Use exactly this form: it is the only push the command guard lets through
without asking (a feature branch, never `main`, no other flags). The pre-push hook runs both third-party checks on every commit; if it refuses,
fix the cause (never `--no-verify`). Then create the PR with
`gh pr create --base main --title "<title>" --body-file <scratchpad>/pr-body.md`,
writing the body to the session scratchpad, not the repo. Follow
`.github/pull_request_template.md`:

```
<template warning block, kept as-is>

## What and why
<2–5 sentences>

## Checks
- ruff, ruff format, mypy, pytest (<N passed>), fixture scan, apps-only scan: pass

## Reviews
### privacy-reviewer
<findings, one line each, or "No findings"> → <what you fixed, with commit>
### report-reader (if run)
…
### allowlist-guard (if run)
…

## Open items
<unresolved findings and questions for the maintainer, or "None">

## Checklist
<template checklist, ticked honestly>

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

The PR is public:
- Reviewer findings stay masked: no app names, identifiers or real
  timestamps, only file, line and kind.
- Report check results as pass/fail only. Never paste check output into a PR
  or commit (the apps check prints how many apps are on the maintainer's list,
  which is itself a fingerprint).
- Before `gh pr create`, run the apps-only check on the body file
  (`uv run appopsy redact-fixture --check --apps-only --third-party-list ~/.config/appopsy/my-apps.txt <scratchpad>/pr-body.md`).
  The command guard runs it again on the title and body and asks if either names
  one of the maintainer's apps.

## 6. Report back

Give the maintainer the PR URL, each reviewer's findings in one or two lines,
what you fixed, and the open items. Batch any questions here, at the end. Do
not merge.
