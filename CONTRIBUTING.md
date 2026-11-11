# Contributing to appopsy

> [!WARNING]
> **Never paste raw dumps, case folders or unredacted reports** into an issue, pull
> request or discussion. They show which apps you have and what they did, and can
> include identifiers from your phone. Use `appopsy report <case> --redact`, **read
> the redacted copy before you share any of it**, and paste only the part you need.

Thanks for helping. Bug reports, new rules and parser fixtures from other Android
versions and manufacturers are all welcome.

## Before you start

- Set up the project as in the README's [Development](README.md#development)
  section, including the git hooks; they run the checks CI runs, plus the privacy
  checks that keep personal data out of the repository.
- For anything bigger than a small fix, open an issue first so we can agree on the
  approach.
- Security problems: don't open an issue. Report them privately, as described in
  [SECURITY.md](SECURITY.md).

## Pull requests

- One change per pull request, with tests. A parser change comes with a test
  against a fixture.
- Fixtures must go through `appopsy redact-fixture` and pass
  `appopsy redact-fixture --check`. Tests and docs use `com.example.*` for apps;
  no real third-party app outside the small set the fixtures allow.
- A new adb command needs the maintainer's agreement first: appopsy only ever runs
  read-only commands from an explicit allowlist.
- Rules explain rather than alarm: say what was seen, why it matters, what is
  probably harmless about it, and what the user can do.

## Code of conduct

This project follows the [Contributor Covenant 3.0](CODE_OF_CONDUCT.md). By
taking part you agree to it.
