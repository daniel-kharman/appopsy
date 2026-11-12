---
name: capture-fixture
description: Capture a new test fixture from the connected phone, redact and time-shift it, run both third-party checks and the privacy-reviewer, delete the raw capture, then stop and show the fixture to the maintainer before anything is committed. Only when the maintainer asks for it.
argument-hint: "[what the fixture is for]"
model: sonnet
disable-model-invocation: true
---

# /capture-fixture

Fixtures from a real phone always need the maintainer (CLAUDE.md, Autonomy).
Invoking this skill is that request, for **one** capture. You never commit,
push or open a PR from here: the last step is showing the maintainer the result.

Read the "Fixtures and redaction" section of `CLAUDE.md` before starting. If
any step fails, stop, report the step and its (masked) output, and delete the
raw capture as in step 6.

## 0. Preconditions

- Working tree clean and on a branch other than `main` (create one,
  `git switch -c fixture-<short-purpose>`, if needed).
- `~/.config/appopsy/my-apps.txt` exists with mode 0600
  (`stat -f %Lp ~/.config/appopsy/my-apps.txt` on macOS). If not, stop and ask.
- `uv run appopsy devices` shows exactly one device in state `device`. If not,
  stop and tell the maintainer what it shows.

## 1. Capture into the scratchpad, never the repo

```
uv run appopsy audit --cases-dir "<scratchpad>/cases"
```

`<scratchpad>` is the session scratchpad directory from your system prompt.
Never pass a path inside the repository. Note the case folder it prints.

## 2. Look only through the mask

All exploration of the raw capture goes through `uv run appopsy mask <file>`.
Print counts and masked shapes, never raw lines. The Android version and
manufacturer are the only raw values you may read directly:

```
grep -E '^\[(ro.build.version.release|ro.product.manufacturer)\]' <case>/raw/getprop.txt
```

If the phone has apps that aren't in `~/.config/appopsy/my-apps.txt`
(compare counts: `pm-list-packages-3p.txt` in the case vs. the list), note
that for the maintainer (the list should be refreshed from this case). Don't
print the names. Counts stay in your report to the maintainer; never put them
in a commit, PR or file in the repo (an app count is a fingerprint).

## 3. Redact, trim and time-shift in one run

The fixture folder is `tests/fixtures/<release>-<manufacturer, lowercase>/capture-<N>`
with `N` one more than the highest existing capture number there.

```
uv run appopsy redact-fixture --third-party-list ~/.config/appopsy/my-apps.txt \
    --out tests/fixtures/<release>-<oem>/capture-<N> <case>/raw
```

This applies the package policy (only the public allowlist of third-party apps
remains), strips identifiers, normalises per-device values, and shifts every
timestamp so the capture sits on 2030-01-01T00:00:00Z. Never pass `--mapping`
(it would write personal data); never redact files from two captures together.
If it refuses (a second capture clock, an unshifted time format), stop: the fix
belongs in `appopsy/redact*.py` with a synthetic test, and that's a separate
change the maintainer should hear about.

If `$ARGUMENTS` says the fixture is for a specific parser or rule, you may
drop files from the fixture folder that aren't needed, but keep the four
required ones (`date-epoch.txt`, `date-local.txt`, `pm-list-packages-3p.txt`,
`pm-list-packages-system.txt`).

## 4. Checks

```
uv run appopsy redact-fixture --check --third-party-list ~/.config/appopsy/my-apps.txt tests/fixtures 2>&1 | uv run appopsy mask
uv run appopsy redact-fixture --check --apps-only --third-party-list ~/.config/appopsy/my-apps.txt . 2>&1 | uv run appopsy mask
uv run pytest -q tests/test_fixtures_clean.py
```

All three must pass. Don't hand-edit the fixture to make one pass unless the
edit is a plain deletion of a whole block owned by a disallowed app, and say
so. If a check still fails, **delete the new fixture folder** (an unclean
fixture left in the working tree is one `git add` from a commit), go to step 6,
and report the masked finding: the fix belongs in the redactor.

## 5. privacy-reviewer

Run the `privacy-reviewer` agent with the scope "the new fixture folder
tests/fixtures/<…>/capture-<N>, read every file; this is a fresh capture from
the maintainer's real phone". Relay its report verbatim.

## 6. Delete the raw capture

Whatever happened above, delete the case folder from the scratchpad
(`rm -rf "<scratchpad>/cases/<case>"`) and confirm it's gone. The fixture in
the repo is now the only copy; the maintainer can re-capture if they reject it.

## 7. Stop and show the maintainer

Do not `git add` or commit. Report:

- the fixture path and `wc -l` of its files (not `ls -la`: owner names and
  real file times don't belong in anything you might paste on);
- `git status --short`;
- the three check results and the privacy-reviewer findings;
- what you dropped from the fixture, if anything, and why;
- whether the app list needs refreshing (step 2);
- that the raw capture was deleted (as `<scratchpad>/cases/<case>`: the case
  folder's name holds the real capture time).

Then wait. The maintainer reviews the diff by hand (CLAUDE.md) and tells you
whether to commit it, at which point `/ship` takes over.
