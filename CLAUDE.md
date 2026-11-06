# appopsy — an autopsy of what your apps have been doing

A read-only Android audit tool. Plug any Android phone in over adb, run one command,
get a plain-English findings report about what installed apps are allowed to do,
what they've actually done, and what they tried to do and were blocked from doing.

Phase 1 is a **privacy** tool (wide audience). Phase 3 adds **security** rules
(stalkerware / persistence). Same engine throughout.

## Principles (non-negotiable)

1. **Read-only, enforced in code.** All adb calls go through one wrapper
   (`appopsy/adb.py`) that only executes commands on an explicit allowlist.
   Anything that changes device state (`pm uninstall`, `pm disable`, `appops set`,
   `settings put`, `am`, `input`, `cmd package`, `reboot`, etc.) is refused with an
   error. Add a test that proves refusal. Never bypass the wrapper.
   **The allowlist only contains commands a collector actually runs** (plus the
   `getprop <key>` lookups `appopsy devices` shows). No "might need it later"
   entries: a command is added in the same change as the collector that runs it,
   after the maintainer approves, and removed when nothing runs it any more. A test runs
   `devices` and a full `audit` against a fake device and fails on any unused rule.
2. **Deterministic first.** Collection, parsing, rules and reporting are plain
   Python. An LLM is an optional final step (`--llm`, Phase 4) and the tool must be
   fully useful without it.
3. **Personal data stays local.** Case folders and reports are gitignored. Never
   commit raw dumps from a real device. Test fixtures must be redacted (see below).
4. **Degrade gracefully.** Output formats drift across Android versions and OEMs.
   A parser that can't understand a section records a `parse_warning` and moves on;
   it never crashes the run.
5. **Explain, don't alarm.** Every finding says what was observed, why it matters,
   what's probably benign about it, and what the user can do.

## Privacy vs security: one engine, two rule packs

The split is by **the question a rule answers**, not by the data it reads.

- **Privacy pack** — "What are the apps I knowingly installed doing with my data
  and sensors?" The app is legitimate; its behaviour is the question. Tone is
  informative; remediation is tuning (restrict battery, narrow a permission,
  uninstall if you choose).
- **Security pack** — "Is something on this device working against me?" The app's
  presence or capabilities are the problem. Tone is alerting; remediation needs care.

Test for any new rule: if every finding were true, would the user say "that's
annoying" (privacy) or "I've been compromised" (security)?

Implementation:
- Everything except rules is **shared**: adb wrapper, collectors, parsers, models,
  rules engine, report renderer. Collectors are not owned by a pack.
- Rules live in `appopsy/rules/specs/privacy/` and `appopsy/rules/specs/security/`
  (inside the package, loaded with `importlib.resources`). The rule schema has a
  required `pack: privacy | security` field **from the first commit**, even
  though Phase 1 ships privacy rules only.
- Separate severity scales so a chatty app never shares a label with possible
  stalkerware: privacy = `info | notable | concern`; security =
  `low | medium | high | critical`. Validate the scale against the pack.
- CLI: `appopsy audit --pack privacy` (default in Phase 1), `--pack security`,
  `--pack all`. The report renders each pack in its own section.
- Grey areas are resolved with **correlation rules** in the security pack that
  consume privacy findings (e.g. over-privileged + sideloaded + accessibility
  service), rather than blurring the packs.

Safety principle for the security pack: a likely-stalkerware finding must **not**
simply say "uninstall it". Removal can alert whoever installed it and, for someone
in an abusive situation, escalate risk. Security remediation text points to
safety-planning resources (e.g. the Coalition Against Stalkerware) before any
removal step. The README says this too.

## Stack

- Python 3.12+, managed with `uv`
- CLI: `typer`; output: `rich` for terminal, Jinja2 for HTML/Markdown reports
- Rules: YAML files in `appopsy/rules/specs/`, validated with `pydantic`
- Tests: `pytest`; lint/format: `ruff`; types: `mypy` (strict on `appopsy/`)
- CI: GitHub Actions running lint, types and tests against fixtures (no device needed)

## Layout

```
appopsy/
  adb.py            # allowlisted, read-only adb runner; device selection; timeouts
  case.py           # case folder writer: raw/, parsed/, manifest.json (0700 dirs, 0600 files)
  redact.py         # identifier detectors shared by redact-fixture and the CI fixture scanner
  redact_packages.py # third-party package allowlist policy for fixtures
  redact_time.py    # shifts every timestamp in a capture onto the anchor, 2030-01-01T00:00:00Z (`ANCHOR`)
  cli.py            # appopsy devices | audit | watch | report | redact-fixture
  collectors/       # one module per source; writes raw text into the case folder
  parsers/          # raw text -> pydantic models / JSON
  rules/engine.py   # loads YAML rules, evaluates against parsed data
  rules/specs/      # YAML rule specs, shipped in the wheel (contributable)
    privacy/
    security/
  report/           # Markdown + HTML templates, redaction
tests/fixtures/<android-version>-<oem>/<capture>/  # one redacted capture per folder (synthetic-*: hand-written)
docs/format-notes.md                      # per-version/OEM output quirks
cases/              # gitignored: <timestamp>-<model>/raw, parsed, report
```

## Phase 1 — privacy MVP (`appopsy audit`)

Collectors (raw output saved verbatim, one file per command):
- `getprop` (model, Android version, security patch level)
- `pm list packages -3 -i` (user apps + installer) and `pm list packages -s`
  (system list; how redaction and the fixture scanner tell system from third-party)
- `dumpsys package packages` (every package's grants in one call) and
  `dumpsys package shared-users` (grants of shared-UID apps live there). Per-app
  `dumpsys package <pkg>` is the only form with `requested permissions:`; it is not
  collected or allowlisted until a rule needs it.
- `dumpsys appops`: one call gives every app's UID-level and package-level modes
  (including the sensitive ops RECORD_AUDIO, CAMERA, FINE/COARSE_LOCATION,
  READ_CONTACTS, READ_CALL_LOG, READ_SMS, READ_MEDIA_*, BODY_SENSORS,
  RUN_ANY_IN_BACKGROUND) and the access/reject history, so per-op
  `cmd appops get <pkg> <OP>` isn't needed (~0.25 s vs ~8 s for about a hundred apps).
- `dumpsys jobscheduler`, `dumpsys alarm`, `dumpsys location` (no arguments)
- `pm query-activities --brief -a android.intent.action.MAIN -c
  android.intent.category.LAUNCHER`: which packages have a launcher icon, to tell
  preinstalled apps people use (Maps, Phone) from platform components. Only this
  exact `pm` form; `cmd package query-activities` stays refused, because `cmd
  package` is refused as a whole (its other subcommands change state). It lists
  every app with an icon, so fixtures go through the package policy and both
  third-party checks like the dumpsys files.
- `date` (epoch and local time), last, so the clock is close to the snapshots

Parsing notes learned from a real Pixel 11 Pro / Android 17:
- appops output has **two layers**: a `Uid mode: OP: <mode>` line (effective
  policy) and a per-package line with `time=` (last allowed access) and
  `rejectTime=` (last denied attempt). Capture both.
- Access states appear as `[top-s]`, `[fg-s]`, `[fgsvc-s]`, `[fg-tpd]`, etc. The
  prefix is the UID state (top/fg/fgsvc/bg, cch = cached, pers = persistent); the suffix is attribution
  (s = self, tp/tpd = trusted proxy / proxied, up/upd = untrusted). Proxied access
  includes `proxy[uid=…, pkg=…]` — record the chain.
- Relative times (`+1m39s241ms`) must be converted to absolute timestamps using
  the device clock at collection time (collect `date` from the device too).
- `dumpsys appops` prints **one Access/Reject line per UID state** (`[fg-s]`,
  `[bg-s]`, …), each with an absolute timestamp plus a relative `(-4h13m…)` that
  changes on every call. Never assume one line per op, and strip the relative part
  before diffing snapshots (a naive diff reports a "new" event on every poll).
- `MONITOR_LOCATION` / `MONITOR_HIGH_POWER_LOCATION` record active location
  **requests**, not deliveries, and are modelled separately
  (`OpCategory.LOCATION_REQUEST`; `GPS` is `LOCATION_HARDWARE`). No rule may report
  a MONITOR_* background access as "location received in background"; only
  FINE/COARSE Access/Reject events (`LOCATION_DELIVERY`) are evidence of delivery
  or denial. Test case: Facebook's `MONITOR_LOCATION [bg-s] duration=+3ms` in
  `tests/fixtures/17-google/capture-1/`.
- A package can appear under a UID that isn't its own (e.g. com.google.android.as
  under 30168 as well as 10168). `link_uids()` classifies UIDs by comparing with
  the package's `appId`, never by UID arithmetic, and reports must label such a UID
  "<package> (secondary UID <uid>)", not as a separate app.
- Real observation to reproduce in tests: Facebook with FINE_LOCATION in
  `foreground` mode produced background rejects roughly every 5–8 minutes while
  the app was closed. `watch` must be able to show that cadence.
- WorkManager jobs expose a worker class name in the job tag
  (`#StoryTrayPredictionPrefetchWorker#`) — extract it; it's the most readable
  evidence in the report.

Phase 1 rules (each a YAML file with id, pack, title, severity, description,
rationale, benign_explanations, remediation):
1. `background-sensor-attempt` — op mode is `foreground` or `ignore` but a
   `rejectTime` exists, i.e. the app tried to use a sensor it wasn't allowed to
   use in that state.
2. `chatty-wakeups` — app's wakeup alarms exceed a threshold per hour.
3. `unconstrained-background-work` — scheduled jobs that require neither
   charging, nor device idle, nor an unmetered network ("any network" is not a
   constraint); list worker names and what each job does require.
4. `over-privileged-app` — informational ranking by **kind of access** (location,
   camera, microphone, contacts, call log, SMS, photos and videos, body sensors,
   background), not by op, with full vs partial (precise vs approximate location;
   whole library vs selected photos). Selected photos only is the privacy-friendly
   choice: shown, never counted or suggested as an action.
5. `sensor-use-summary` — informational: who used mic/camera/location recently,
   in which state, for how long.
6. `background-sensor-use` — a sensor access allowed and delivered while the app
   wasn't on screen (bg/cch/fgsvc Access events; deliveries only, never MONITOR_*).
   Notable for location and body sensors. Microphone or camera: concern when
   delivered in bg/cch, notable when only via fgsvc (Android shows a notification and
   the privacy indicator while a foreground service uses them; e.g. the Google app).
   A spec may declare extra `severities:` its function picks per finding.

Headline (`build.headline`): one sentence per kind of finding, concern first,
naming at most three apps then "and N more". The sensor rules split by sensor
(and camera/microphone by visible vs background use), so different sensors are
never merged across apps in one clause.

Report rules: every "What you can do" app line gives a concrete step (a Settings
path) or is omitted, and never suggests narrowing an app's core-function access
(`core:` in `appopsy/report/apps.yaml`, e.g. Phone: contacts, call log).

Rules engine (`appopsy/rules/`):
- Rule **logic lives in registered, typed Python functions**
  (`@rule_function("<id>", thresholds=...)` in `appopsy/rules/<pack>.py`). The YAML
  spec holds id, pack, title, severity, thresholds, description, rationale,
  benign explanations and remediation, and names its function by id. **No YAML
  condition language.** Loading refuses a spec whose severity isn't on its pack's
  scale, whose thresholds differ from what its function declares, or that has
  unknown keys.
- **Every threshold cites its source** (title, URL, date checked, `verified`, and a
  note when it couldn't be confirmed). Never tune a threshold to make a particular
  app fire; if an app is under a threshold, the test asserts it doesn't fire.
- **Every finding carries evidence**: case-folder file plus line numbers, so the
  report can cite raw lines. Parsers record line numbers for this.
- **System apps are framed centrally** (`make_finding`): `classify()` splits system
  packages into `preinstalled` (has a launcher icon: Maps, Phone) and `system`
  (platform components: android, Play services, Android System Intelligence).
  Preinstalled apps are framed like installed ones, marked "came with the phone".
  Findings about platform components go to the "system" section at the pack's
  lowest severity, never alongside apps. `hiddenFromAppOps` location requests
  always go there too. Cases without the launcher query treat every system
  package as `system`. See `docs/rule-ideas.md`.

Report (`appopsy/report/`): one view model (`build.py`) rendered as Markdown and as a
single self-contained HTML file (inline CSS; no scripts, fonts or anything loaded
from the network, so opening a report contacts nobody; autoescaped). Summary table, findings by severity, per-app detail, and a "what you can
do" section (e.g. set battery to Restricted, change permission to "Only while
using"). `--redact` (`appopsy/report/redaction.py`) writes a shareable copy:
apps that aren't system packages or in the bundled name map are shown as
"Unlisted app <id>", the id an HMAC under a key made fresh per render (not
reversible by hashing popular names; two reports can't be linked), and their
job, alarm and request names are hidden unless a public app in the same report
shows the same name. Times become days relative to collection ("today", "3 days
ago"); unredacted reports keep exact times. The text is then checked, by whole
name, for any private name, for device identifiers (`redact.identifiers`) and
for any exact time; a hit refuses to write.

Report length (target: main report under ~600 lines on a full phone; detail in
appendices): the access ranking, recent sensor use, and background work (installed
apps' and, at info, preinstalled apps') are each one compact table in the main
report, with per-app detail in an appendix (the ranking's appendix covers only apps
allowed something at any time). Per-app detail is one line per app linking to its
rule sections; system components are one table, a row per finding, with notes
(e.g. Play services) kept and each finding in an appendix. Job names several apps
schedule are labelled with their library and listed once in a "Shared job
libraries" table; repeated jobs within an app merge with a count. Markdown links
use GitHub heading slugs (`markdown.resolve_anchors`); in HTML, appendices and
tables over 10 rows fold into `<details>` (no scripts). `docs/sample-report.{md,html}` is generated from capture-5 with
`--redact`; a test fails when it's stale.

## Phase 2 — `appopsy watch`

Poll selected sources on an interval, record only *changes* (new access, new
rejectTime, new alarm/job) to a JSONL timeline, then render a timeline report.
Motivating case: repeated rejected background-location attempts that a snapshot
can't characterise (one-off vs periodic, and what triggered them).

## Phase 3 — security pack

Accessibility services, device admins, notification listeners, default
SMS/dialer handlers, sideloaded apps (installer not Play), apps hiding their
launcher icon, plus correlation rules. Pitch: "check your own phone for
stalkerware". Follow the safety principle above.

## Phase 4 — `--llm`

Optional triage/summary of the parsed findings. Send parsed JSON, never raw dumps.

## Fixtures and redaction

Before adding a fixture, run `appopsy redact-fixture`, which strips serials,
IMEIs, account names, emails, phone numbers, SSIDs, MAC/IP addresses and
location coordinates, plus the per-SIM carrier properties (`gsm.operator.*` and
`gsm.sim.operator.*`: name, MCC-MNC, country). It also neutralises values that
reveal where the owner lives or is: `persist.sys.timezone` becomes `Etc/UTC`;
`persist.sys.locale`, `ro.product.locale` and the older language/country/region
properties become `en-US`. Replacement is consistent across files.

**Time shift.** Timestamps say when the owner used each app, so every timestamp in
a capture is moved by **one constant offset** so that the capture happens at
`2030-01-01T00:00:00Z` (`ANCHOR` in `appopsy/redact_time.py`, the only place it is set:
later than any real build or security patch date, so ages computed from
fixtures are never negative), and written in UTC. The offset belongs to the capture, not
the file: every file in a capture folder (date files, getprop boot times,
dumpsys package, appops, and future jobscheduler/alarm dumps) gets the same
shift, so intervals, cadences and relative times like `(-21m14s)` stay valid.
Local wall-clock times are converted with the device's timezone (DST-aware)
before shifting. Covered formats: `YYYY-MM-DD HH:MM:SS[.fff]`, year-less
`MM-DD HH:MM:SS:fff`, `date` ISO output, the epoch in `date-epoch.txt`, 13-digit
epoch milliseconds, and getprop boot times. Not shifted: build dates (same on
every device), times relative to boot, and install/update times (normalised to
`2000-01-01 00:00:00`). `redact-fixture` refuses inputs with more than one
capture clock, or timestamps without one; CI fails on any time after the anchor.
Code: `appopsy/redact_time.py`. When a new source has a new time format, add it
there before committing the fixture.

**Capture folders.** Every multi-file fixture is its own capture folder,
`tests/fixtures/<android-version>-<oem>/<capture>/`, containing only files from
one `audit` run, including that run's `date-epoch.txt`, `date-local.txt`,
`pm-list-packages-3p.txt` and `pm-list-packages-system.txt`. Redact a capture
folder as one `redact-fixture` run, never files from several captures together.
CI checks that every non-synthetic folder has those four files and that its
clock sits on the anchor.

Installed apps are personal too. Fixtures keep system packages as they are, but
the only third-party packages allowed are a fixed public set: `com.twitter.android`,
`com.facebook.katana`, `com.facebook.orca`, `com.whatsapp`, `com.tencent.mm`, plus
the synthetic sideloaded `com.example.sideloaded` (non-Play installer).
`redact-fixture` rewrites `pm list packages` output to that set, drops other
third-party apps from `dumpsys` output (e.g. the device-wide `Queries:` section),
and normalises install/update timestamps, random `/data/app/~~…==` path segments
and domain-verification IDs. `--packages FILE` substitutes your own allowlist.
No other real third-party package may appear in any fixture, test or doc; tests
use `com.example.*` / `org.example.*` for disallowed apps.

**General rule: any value that is random or assigned per device or per install
is normalised**, even if it doesn't look personal, because it can link a fixture
back to one phone. Today that covers hardware IDs (`ro.boot.hw.soc.id`,
`vendor.modem.soc_id`, `ro.boot.cdt_hwid`), install/update timestamps,
`/data/app/~~…==` segments, domain-verification IDs, theme overlay `.frro`
suffixes, data-directory inode numbers, signing keyset IDs, carrier IDs inside
property names (`....carrier<N>`) and the setupwizard compliance date. When a new
source shows a new one, add it to `appopsy/redact.py` before committing the
fixture. Kept on purpose: values that change every boot (object hashes such as
`Package{f39ba71 …}`, `cache_key.*`), values shared by every device on a build
(fingerprints, partition digests, build UUIDs), and app UIDs (rules join appops
to packages by UID).

**Jobs and alarms.** No Phase 1 rule needs network details, so NetworkRequest /
capability / transport lines and the ConnectivityController body are dropped (they
can reveal VPN use and the VPN app's UID). Job `Extras` bundles are free-form app
data and become `{REDACTED}`. Job IDs get placeholders scoped to the capture, so
nothing links across captures. Blocks owned by a non-allowed app go whole (job
blocks, completed-job entries, alarm entries and stats), and a block owned by a
bare UID is kept only if the capture shows all of that UID's packages are allowed.
**Location.** Every `Location[...]` record is replaced whole
(`Location[<provider> REDACTED]`): altitude, speed and bearing locate a person as
well as coordinates. Geofence entries are dropped (they can encode home or work).
The CI scan flags any coordinate-shaped lat/long pair or labelled lat/lon anywhere
in a fixture, not only inside known record formats.

Totals that describe what a file lists (`Registered N jobs:`, `N pending alarms:`)
are recounted from what the fixture actually contains, so trimming never leaves
them inconsistent; independent statistics (per-UID counts, battery level) stay.

`tests/test_fixtures_clean.py` fails CI if anything is left. Review the diff by
hand before committing.

Raw captures used to build a fixture (case folders, raw dumps, mapping files)
live only in the scratchpad, never in the repo. Once the fixture is committed,
delete them from the scratchpad and tell the maintainer that you have.

**Exploring raw captures.** All exploration of raw captures goes through the
masking helper, `uv run appopsy mask <file>` (reads `~/.config/appopsy/my-apps.txt`),
never through ad-hoc masks: a hand-written pattern missed `net.*` names and printed
class names attached to masked packages. The helper masks the whole token around
each of your apps, including attached class names, actions and WorkManager tags.
Print counts and masked shapes, not raw lines.

**Your own app list (local only).** CI can only check structural positions
against the allowlist; it never sees the real list, so it can't catch a real app
name in prose, a test, or inside a permission name. That check is local. The
list lives **outside the repo** at `~/.config/appopsy/my-apps.txt` (mode 0600;
`redact-fixture` refuses a list inside a git working tree). Refresh it from a
case folder: `cp cases/<case>/raw/pm-list-packages-3p.txt
~/.config/appopsy/my-apps.txt`. Before any push that touches fixtures or docs
(in practice, before every push), run both and push only if they pass:

```
uv run appopsy redact-fixture --check --third-party-list ~/.config/appopsy/my-apps.txt tests/fixtures
uv run appopsy redact-fixture --check --apps-only --third-party-list ~/.config/appopsy/my-apps.txt .
```

The first is the full fixture scan plus your apps; the second looks for your
apps anywhere in the repo (`--apps-only` because tests and code contain
synthetic identifiers on purpose). Pass `--third-party-list` when building a
fixture too, so the redactor knows every app even if the input lacks a `pm list`.

## Working style

- The git hooks in `.githooks/` enforce the commit discipline (install:
  `git config core.hooksPath .githooks`). pre-commit checks the staged tree with
  ruff, mypy and pytest; pre-push runs both third-party checks on every commit
  being pushed and fails closed without the app list. Never bypass them with
  `--no-verify`; if a hook is wrong, fix the hook.
- Small, reviewable commits; one collector/parser/rule at a time, with tests.
- Write the parser test against a fixture before the parser.
- When a format is ambiguous, ask rather than guess, and note it in
  `docs/format-notes.md`.
- Stop and check in with the maintainer at each phase boundary and before any change to
  the adb allowlist.
- Prior art to read and credit, not copy: Amnesty MVT, androidqf, Exodus Privacy.
  README must explain how appopsy differs (rules-driven, consumer-readable, privacy-first).
