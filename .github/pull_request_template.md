> [!WARNING]
> **No data from a real phone in this PR**: no raw dumps, case folders or unredacted
> reports, in code, tests, fixtures or this description. Fixtures go through
> `appopsy redact-fixture`; examples come from a redacted report you've read.

## What and why

## Checklist

- [ ] One change, with tests (a parser change has a fixture test).
- [ ] The git hooks ran (`git config core.hooksPath .githooks`), and the privacy checks passed.
- [ ] No real third-party app names outside the fixture allowlist; examples use `com.example.*`.
- [ ] No new adb command (or the maintainer agreed to it first).
