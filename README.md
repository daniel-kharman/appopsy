# appopsy

**An autopsy of what your apps have been doing.**

appopsy is a read-only Android audit tool. Plug in any Android phone over USB, run
one command, and get a plain-English report on what your installed apps are
allowed to do, what they've actually done, and what they *tried* to do and were
blocked from doing.

It's named after **AppOps**, the Android subsystem that tracks every app's access
to sensitive operations, and the subsystem appopsy interrogates most.

> **Status:** early development. Phase 1 (privacy audit) is in progress.

## Why

Android records far more about app behaviour than its Settings screens show. A
single `adb` command reveals, for example, that an app with location set to
"Only while using the app" is still asking for your location from the background
every few minutes, and being refused each time. appopsy turns those raw system
dumps into findings anyone can read.

## What it looks at

**Privacy pack** (Phase 1, default)
- Sensor use: who used the mic, camera and location, when, in what state, for how long
- **Blocked background attempts:** apps trying to use sensors they aren't allowed to use in that state
- Chatty wakeups: apps that repeatedly wake your phone from sleep
- Unconstrained background work: scheduled jobs that run anytime, on battery and mobile data
- Over-privileged apps, ranked by the sensitive permissions they hold

**Security pack** (Phase 3)
- Accessibility services, device admins and notification listeners
- Sideloaded apps and apps hiding their launcher icon
- Correlation rules for stalkerware-like combinations

The two packs share one engine but answer different questions. Privacy asks
*"what are the apps I chose doing?"*; security asks *"is something here working
against me?"*

## Design principles

- **Read-only, enforced in code.** Every adb call passes through an allowlist.
  Anything that would change your device is refused.
- **Deterministic first.** Plain Python collectors, parsers and YAML rules. An
  optional `--llm` summary may come later; the tool never depends on it.
- **Your data stays on your machine.** Reports are written locally and are never
  uploaded. `--redact` produces a shareable version.
- **Explain, don't alarm.** Every finding says what was seen, why it matters, what
  is probably benign about it, and what you can do.

## Quick start (planned)

```bash
# Requirements: Python 3.12+, uv, and adb (Android platform-tools)
# On the phone: enable Developer options and USB debugging, then authorise this computer

uv tool install appopsy        # not yet published
appopsy devices                # confirm the phone is connected and authorised
appopsy audit                  # collect, run the privacy rules, write the report:
                               #   ./cases/<timestamp>-<model>/report/report.{md,html}
appopsy audit --pack all       # privacy and security rules
appopsy report cases/<case>    # re-render a case later, without the phone
appopsy report cases/<case> --redact   # a copy you can share: report-redacted.{md,html}
appopsy watch --app com.example.app   # record changes over time
```

## Sample report

[`docs/sample-report.md`](docs/sample-report.md) ([HTML](docs/sample-report.html)) is a
full report made from the test fixture `tests/fixtures/17-google/capture-5`: a real
Pixel 11 Pro capture with personal data redacted, timestamps shifted and every
third-party app except a small public set removed. It was generated with

```bash
appopsy report tests/fixtures/17-google/capture-5 --redact -o docs/sample-report.md
```

It opens with a short headline:

> Google Maps received your location while not on screen. Facebook, WeChat and WhatsApp tried to use your location in the background and were refused, because your settings allow it only while the app is in use. Facebook (14) and Messenger (3) have background jobs that can run on battery and mobile data at any time, 17 in all. Google Maps, which came with the phone, has the broadest access: 6 of the 9 kinds of sensitive access appopsy checks, including your precise location, contacts, photos and videos at any time.

then a summary, the findings (each with what it means, why it matters, what's
probably harmless and the raw lines it rests on; long groups as one table), a line
per app linking to its findings, concrete steps, the platform components, how each
threshold was chosen, and appendices with the full detail.

## If you're worried about stalkerware

If you think someone has installed monitoring software on your phone, **don't
remove it straight away**. Removal can alert the person who installed it. Talk to
a support service first, such as the
[Coalition Against Stalkerware](https://stopstalkerware.org/), and make a safety
plan. The security pack's findings follow this guidance.

## How appopsy differs from existing tools

- **[Amnesty MVT](https://github.com/mvt-project/mvt) / [androidqf](https://github.com/mvt-project/androidqf):**
  forensic tools for investigators, focused on known spyware indicators. appopsy
  is aimed at everyday users and focuses on the behaviour of ordinary apps.
- **[Exodus Privacy](https://exodus-privacy.eu.org/):** static analysis of trackers
  inside app packages. appopsy looks at what apps actually did on *your* phone.

appopsy is rules-driven and built for readable reports. Rules are YAML files, and
contributions are welcome.

## Development

```bash
uv sync                                  # create .venv with the dev tools
git config core.hooksPath .githooks      # install the git hooks (once per clone)
```

The hooks are checked into `.githooks/`:

- **pre-commit** runs `ruff check`, `ruff format --check`, `mypy` and `pytest` on
  exactly what is being committed (the staged files, not your working tree).
- **pre-push** runs the two privacy checks on **every commit being pushed**: the
  fixture scan, and a search of each tree and commit message for apps on your own
  installed-app list. The list is personal and lives outside the repository, at
  `~/.config/appopsy/my-apps.txt`; without it the push is refused. See
  `CLAUDE.md` ("Your own app list") for how to create it.

`git commit --no-verify` / `git push --no-verify` skip them; don't, unless you know
why a check is wrong and fix the check.

## Contributing

Rules live in `appopsy/rules/specs/privacy/` and `appopsy/rules/specs/security/`:
a YAML spec per rule, plus its registered function in `appopsy/rules/<pack>.py`.
Parser fixtures from
different Android versions and manufacturers are especially valuable; please run
`appopsy redact-fixture` on any dump before submitting it.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
