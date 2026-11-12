---
name: post-launch-check
description: Read-only audit of the GitHub repo's settings with gh api GET requests. Covers visibility, the main-branch ruleset, security features (private vulnerability reporting, secret scanning, push protection, Dependabot, code scanning), Actions permissions, open alerts, failed runs, and community files. Reports only and changes nothing.
argument-hint: "[owner/repo]"
model: sonnet
---

# /post-launch-check

Audit how the public repository is configured. **Read-only:** use only
`gh api <path>` GET requests (no `-X`/`--method`, no `-f`/`-F`/`--field`/`--input`;
the command guard hook makes any of those ask the maintainer). Don't use other
`gh` subcommands; `gh repo …` asks for permission on purpose. Change nothing,
even when something is wrong: report it with the exact setting and where to
change it, and let the maintainer decide.

Repository: `$ARGUMENTS` if given, else the `owner/name` part of
`git remote get-url origin`. Call it `R`.

## Queries

Run them in a few batched commands. On a 404/403, record "not available or no
access" for that item and carry on.

1. Repo: `repos/$R`: `visibility`, `default_branch`, `security_and_analysis`,
   `allow_squash_merge`, `allow_merge_commit`, `allow_rebase_merge`,
   `delete_branch_on_merge`, `has_wiki`, `has_projects`.
2. Rulesets: `repos/$R/rulesets`, then each `repos/$R/rulesets/<id>`
   (`enforcement`, `conditions`, `bypass_actors`, `current_user_can_bypass`,
   `rules`), and the effective rules `repos/$R/rules/branches/main`.
3. Security features: `repos/$R/private-vulnerability-reporting`,
   `gh api -i repos/$R/vulnerability-alerts` (204 = on, 404 = off),
   `repos/$R/automated-security-fixes`, `repos/$R/code-scanning/default-setup`.
4. Open alerts (counts only): `code-scanning/alerts?state=open`,
   `secret-scanning/alerts?state=open`, `dependabot/alerts?state=open`.
5. Actions: `repos/$R/actions/permissions`,
   `repos/$R/actions/permissions/workflow`,
   `repos/$R/actions/permissions/selected-actions`,
   `repos/$R/actions/permissions/fork-pr-contributor-approval`; failed runs
   `repos/$R/actions/runs?status=failure&per_page=20`; workflows on `main`
   (`repos/$R/contents/.github/workflows?ref=main`) and whether every `uses:`
   is pinned to a full SHA.
6. Housekeeping: `repos/$R/community/profile` (files present), open PRs,
   branches other than `main`, labels (is `security-sensitive` there?),
   releases and tags.

## Expected (from CLAUDE.md and docs/decisions.md)

| Setting | Expected |
| --- | --- |
| Visibility | public (after launch) |
| `main` ruleset | active; pull request required; status check `ci-ok` required; non-fast-forward (force push) and deletion blocked; no bypass actors |
| Private vulnerability reporting | enabled |
| Secret scanning, push protection | enabled |
| Dependabot alerts and security updates | enabled |
| Code scanning | default setup configured, no open alerts |
| Workflow token default | read; can't approve PR reviews |
| Fork PR workflows | need approval for outside contributors |
| Actions | pinned to full commit SHAs |
| Labels | `security-sensitive` exists (used by the sensitive-paths workflow) |
| Community | README, LICENSE, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, issue and PR templates |

## Report

A table: setting, expected, actual, ✅/⚠️/❌, and for each ⚠️/❌ where to fix
it (Settings path or the API endpoint the maintainer could use). Then a short
list of anything unexpected (failed runs, stray branches, open alerts). Don't
print secrets, tokens or alert contents, only counts. End with "Nothing was
changed."
