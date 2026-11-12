# Design decisions

The key choices behind appopsy, one short entry each: what we decided and why.
Before changing one of these, read its entry. If the reason no longer holds,
update the entry in the same pull request as the change.

## 1. Read-only, enforced by an exact-token allowlist

**Decision.** Every adb call goes through `appopsy/adb.py`, which runs a command
only if it matches an allowlisted shape token by token. Variable tokens must
fully match strict patterns that can't carry shell metacharacters. The list
holds only commands a collector runs today; a test fails on any unused rule.
New entries need the maintainer's approval.

**Why.** "Deny known-bad" doesn't work on Android: even `dumpsys` changes state
(`dumpsys battery set level 5`, `dumpsys deviceidle force-idle`), and `adb shell`
passes its arguments through the device's `sh`, so `getprop; reboot` is one
token away. An exact list makes "read-only" checkable by reading one file, and
keeping it minimal means every entry has a reviewer and a reason.

## 2. Privacy and security packs, with separate severity scales

**Decision.** One engine and two rule packs, split by the question a rule
answers. Privacy asks "what are my apps doing?" (`info | notable | concern`).
Security asks "is something working against me?" (`low | medium | high |
critical`). Loading refuses a severity that isn't on its pack's scale.
Correlation rules in the security pack consume privacy findings.

**Why.** An app that wakes the phone too often and possible stalkerware must
never share a label. Different tone and remediation follow from that:
privacy suggests tuning, while security points to safety planning before any
removal, because removing stalkerware can alert whoever installed it.

## 3. Fixture timestamps shifted to 2030-01-01T00:00:00Z

**Decision.** `redact-fixture` moves every timestamp in a capture by one
constant offset, so the capture happens at `ANCHOR` (`appopsy/redact_time.py`).
Local times are converted with the device timezone (DST-aware) first. CI fails
on any time after the anchor.

**Why.** Timestamps show when the owner used each app and can hint where they
live. One offset per capture keeps intervals, cadences and relative times
valid, so the rules still see the real pattern. A date later than any real
build or patch date means ages computed from fixtures are never negative, and
an obviously fake year can't be mistaken for real data.

## 4. A location request isn't a delivery

**Decision.** `MONITOR_LOCATION` / `MONITOR_HIGH_POWER_LOCATION` are modelled as
`LOCATION_REQUEST`. Only `FINE`/`COARSE_LOCATION` Access/Reject events count
as `LOCATION_DELIVERY`. No rule reports a `MONITOR_*` background entry as
"location received in background".

**Why.** `MONITOR_*` records that an app had a location request open, not that
it got a fix. Treating it as delivery would accuse apps of tracking that
didn't happen (e.g. a 3 ms `MONITOR_LOCATION [bg-s]` entry). Reports must say
only what the evidence supports.

## 5. Foreground service vs real background for the microphone and camera

**Decision.** Microphone or camera use while the app was in the background or
cached (`bg`/`cch`) is a **concern**. Use only from a foreground service
(`fgsvc`) is **notable**.

**Why.** Android shows a notification and the privacy indicator while a
foreground service uses the microphone or camera, so the owner could have
seen it (e.g. a voice assistant). Use in the true background had no such
signal. Merging the two would either cry wolf or understate the second.

## 6. "Came with the phone", decided by the launcher icon

**Decision.** System packages with a launcher icon (Maps, Phone) are
`preinstalled` and reported like installed apps, marked "came with the
phone". Those without one (and `PLATFORM_WITH_ICON`, e.g. Settings) are
platform components. They go to a separate system section at the pack's
lowest severity. Without the launcher query, every system package counts as
`system`.

**Why.** People use preinstalled apps and can restrict them, so hiding them
would leave out real choices. Platform components can't be meaningfully tuned,
and reporting them alongside apps would bury what the owner can act on. The
launcher query is a read-only, version-stable signal that matches how people
see their phone.

## 7. Redaction aliases every installed app

**Decision.** In a `--redact` report every app the user installed, however
well known, becomes "Installed app <id>". The id is an HMAC under a key made
fresh for each render. Only system components and preinstalled apps keep
their names, and times become relative. A final scan refuses to write if any
private name, identifier or exact time remains.

**Why.** The set of apps someone installed is personal, even when each app is
popular. A list of "safe to name" apps would still reveal which of them this
person has. A fresh key means two reports can't be linked and aliases can't be
reversed by hashing popular package names.

## 8. Wikidata names are for display only

**Decision.** `appopsy/report/app_names.tsv` (CC0, generated from Wikidata,
never hand-edited) only supplies friendly names. Redaction treats only system
packages and `apps.yaml` as public; a name in this file doesn't make an app
public. The file is exempt from the apps-only check only while it validates,
and any change must verify against Wikidata before it can be pushed.

**Why.** The file lists every app on Wikidata, so it necessarily names some of
anyone's apps without saying which. Letting it decide what is public would
undo decision 7. The strict format and the verification step stop it from
becoming a way to slip a real app list (or markup) into the repo.

## 9. Every threshold cites a source, or there is no threshold

**Decision.** Each rule threshold records its source (title, URL, date checked,
`verified`, and a note when it couldn't be confirmed). A rule without a
defensible number says so ("No threshold: …") and uses a different design,
such as reporting every case at a low severity in a compact table. Thresholds
are never tuned to make a particular app fire; a test asserts that an app
under a threshold doesn't fire.

**Why.** A number like "N wakeups per hour" is what users will quote back. If
it isn't grounded, the finding is opinion presented as measurement. Being
honest about where no number exists is better than inventing one.

## 10. Launch: squash into a new repository

**Decision.** For the public launch, the code is published as a single
squashed commit in a **new** GitHub repository. The pre-release history is
kept privately and never published. Personal values found at HEAD were
replaced with synthetic ones first.

**Why.** An audit of the full history found personal values in old commits
and paths that no longer exist at HEAD. Squashing removes every history-only
item in one step; filtering would need each one cleaned, commit messages too.
A new repository also leaves behind GitHub's copies of old commits, orphaned
objects and Actions logs, which rewriting history in place would not remove.

## 11. A command guard that fails closed, with known limits

**Decision.** `.claude/settings.json` pre-approves routine commands, and
`.claude/hooks/command_guard.py` reads every Bash, Read, Grep and Glob call to
keep them routine. It refuses anything it can't fully account for: shell
expansions, unknown flags, unhandled git or gh subcommands, private paths
(`cases/`, `reports/`, `*.case/`, in any letter case). It answers "ask" (deny
for the reviewer agents) when it refuses, crashes or runs out of time. Reviewer
agents read files only through Read, Grep and Glob inside the repo; their Bash
has no file-reading tools, and the app list is readable only through
`redact-fixture --check --third-party-list`.

**Why.** Permission rules match only a command's prefix, so `git commit *`
also approves `git commit -n`, which skips the hooks. Each review of the guard
found shell or tool behaviour that a list of known-bad forms missed (on some
machines `grep`, `cat` and `ls` are ugrep, bat and eza), so the guard allows
only what it understands.

**Known limits** (accepted; the guard reduces risk, it isn't a sandbox):
- `uv run pytest` runs the branch's code with the user's rights, and may sync
  dependencies from the network. Reviewers running tests run the code under
  review. External contributors' branches therefore only run in the sandbox or
  a devcontainer.
- `appopsy mask` reads the app list to mask it, so piping chosen text into it
  answers "is this one of my apps". Reviewers need it, so it stays.
- Private folders are refused by path. A recursive search from an allowed
  subdirectory still reaches a `cases/` folder nested under it, and a symlink
  or hard link inside the repo beats the path checks once someone creates it.
- Programs configured in git config or attributes (textconv, `diff.external`,
  filters, fsmonitor) run under read-only git commands.
- A PR body or commit message file is checked for app names, not for other
  identifiers. Raw captures stay out of reach by path (scratchpad bodies must be
  `.md` files directly in it), not by content.
- The guard relies on Claude Code calling it. The hard boundary is the
  sandbox (entry 12), which says which of these limits it closes.

## 12. The Claude Code sandbox is the security boundary

**Decision.** `sandbox` in `.claude/settings.json` runs every Bash command,
and everything it starts (`uv run`, pytest, the pre-commit hook, git config
programs), in an OS-level sandbox (Seatbelt on macOS):

- **No network.** `deniedDomains: ["*"]` with nothing allowed. A project file
  can't make an allowlist strict (unlisted hosts follow the permission mode,
  and auto mode lets them through; `strictAllowlist` is user or managed only),
  but a deny list holds in every mode.
- **Writes** go only to the repo and temp. Claude Code itself also protects
  `.claude/settings.json`, `.claude/hooks/` and `.claude/skills/` from shell
  writes.
- **Reads** of credentials (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.netrc`,
  `~/.git-credentials`, `~/.config/gh`, `~/.docker`, `~/.kube`, the keychains)
  and of the repo's `cases/` and `reports/` are denied.
- **No escape:** `allowUnsandboxedCommands: false` (Claude can't retry a
  blocked command outside the sandbox), and `failIfUnavailable: true` (no
  sandbox, no session).
- **Six exclusions** run outside it, because they need GitHub or the phone:
  `git push -u origin *`, `gh pr create *`, `gh pr view *`, `gh api *`,
  `uv run appopsy devices`, `uv run appopsy audit *`. They're excluded only
  when issued alone: anything chained to them (`;`, `&&`, a pipe) keeps the
  whole line sandboxed, so an exclusion can't carry a second command out.
  Untrusted code can't trigger them; only commands Claude issues match.
- **uv** uses a repo-local cache (`UV_CACHE_DIR=.uv-cache`, offline): sandboxed
  code must not write the shared `~/.cache/uv` that other projects install
  from. When dependencies change, the maintainer runs `uv sync` outside the
  sandbox.
- `autoAllowBashIfSandboxed: false`: the permission rules and command guard
  still decide what runs without a prompt. The sandbox contains what runs; it
  doesn't widen it.

The app list stays readable inside the sandbox: `/ship`'s checks and `mask`
need it. With no network, code that reads it has nowhere to send it.

**Why.** The command guard reads command text, and every review found text it
misread (entry 11). The sandbox is enforced by the operating system on what
a process actually does, so it holds however a command is spelled, and it
covers code nobody typed: tests, dependencies, git config programs.

**Entry 11's limits against the sandbox:**

| Limit (entry 11) | With the sandbox |
| --- | --- |
| `uv run pytest` runs the branch's code with the user's rights and may sync dependencies from the network | **Mostly closed.** That code now has no network, can't write outside the repo and temp, and can't read credentials, `cases/` or `reports/`. It can still read other files (the app list, the rest of the home directory) and change files in the repo; with no network, it has nowhere to send them, and the pre-push scan checks the repo before anything leaves. Dependency syncs no longer happen inside. **Not closed for untrusted branches:** see below. |
| `appopsy mask` answers "is this one of my apps" | **Remains**, by design. The answer goes to whoever runs the command (the session, or code in the sandbox), and from the sandbox it can't go any further. |
| Recursive searches reach nested private folders; symlinks and hard links beat the path checks | **Partly closed.** In Bash, the top-level `cases/` and `reports/` can't be read, whatever path or symlink leads there (Seatbelt checks the real path). Hard links, private folders nested elsewhere, and the Read, Grep and Glob tools (which aren't sandboxed) still rely on the guard's path checks. |
| Programs set in git config or attributes run under read-only git | **Closed** for every git command in Bash: they run sandboxed. **Remains** for the excluded `git push`, whose pre-push hook and config run outside (on the maintainer's own branches). |
| PR body and commit message files are checked for app names only | **Remains.** `gh pr create` runs outside the sandbox and reads its body file there, so the guard's path rules (a scratchpad `.md`, or a repo file outside private folders) are still the control. Commit message files are read by sandboxed git, so `cases/` is unreadable there. |
| The guard relies on Claude Code calling it | **Closed for Bash:** the sandbox is enforced by the OS, whatever the guard decides. **Remains** for Read, Grep and Glob (permission rules and the guard only), hooks, and the six exclusions. |

**What the sandbox doesn't cover** (and the guard, permission rules or a
devcontainer must):
- **Command hooks run outside it, with full access**, and so does any repo code
  they run (the guard's apps check runs `.venv/bin/appopsy`). The hooks and
  settings come from the checked-out branch, and a branch's settings can turn
  the sandbox off. **So the sandbox protects the maintainer's own work, not an
  untrusted branch**: external contributors' branches only run in a
  devcontainer (CLAUDE.md).
- Read, Grep, Glob, Edit and Write follow permission rules and the guard, not
  the sandbox.
- The six excluded commands run with full access when issued alone. Each is
  narrowed by permission rules and the guard (a feature-branch push, GET-only
  `gh api`, a checked PR body), and `uv run appopsy audit` only runs when the
  maintainer starts `/capture-fixture`.
- On native Windows there is no sandbox; `failIfUnavailable` makes Claude Code
  refuse to start rather than run without it.
