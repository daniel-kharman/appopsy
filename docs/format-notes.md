# Format notes

Per-command, per-Android-version and per-OEM quirks in adb output. Add an entry
whenever a parser has to handle something surprising, and link the fixture.

## `adb devices -l` (host side, all versions)

- Lines are `<serial> <state> [key:value ...]`. Attributes seen: `usb`, `product`,
  `model`, `device`, `transport_id`. Missing attributes are normal (e.g.
  `unauthorized` devices usually report only `usb` and `transport_id`).
- The state can contain spaces: on Linux without udev rules it is
  `no permissions (missing udev rules? ...); see [http://...]`. The parser peels
  known `key:value` attributes off the end and treats the rest as the state.
- Serials vary: USB serials, `ip:port` for TCP, and mDNS names like
  `adb-<serial>-<id>._adb-tls-connect._tcp` for wireless debugging.
- When the server is cold, `* daemon not running; starting now ...` lines appear
  before the header. They are ignored.
- `model` uses underscores for spaces (`Pixel_11_Pro`).

## `getprop` (Android 17, Pixel 11 Pro: `tests/fixtures/17-google/capture-1/getprop.txt`)

- One `[key]: [value]` per line, sorted by key. Empty values are `[]`.
- **Values can span lines.** `persist.sys.boot.reason.history` opens `[` on the
  key line and closes `]` at the end of a later line. The parser joins them with
  `\n`. An unclosed value becomes a `parse_warning`.
- Dual-SIM devices report comma-separated per-slot values
  (`gsm.operator.alpha`, `gsm.sim.operator.numeric`, ...). Slots can be empty
  (`[,au]`).
- Personal values found here: `ro.serialno`, `ro.boot.serialno`,
  `ro.boot.vbmeta.device` (PARTUUID), `gsm.sim.preiccid_*` (ICCID prefix), and
  carrier/country per SIM, which together reveal home country and roaming
  location. `redact-fixture` handles all of these.
- `persist.sys.timezone` and `persist.sys.locale` / `ro.product.locale` (older
  releases: `persist.sys.language`, `persist.sys.country`,
  `ro.product.locale.language`, `ro.product.locale.region`) also hint at where
  the owner is. `redact-fixture` neutralises them to `Etc/UTC` / `en-US`.
- `ro.build.uuid` / `ro.build.fingerprint` / `ro.boot.vbmeta.digest` are per
  build, not per device.
- **Per-chip hardware IDs:** `ro.boot.hw.soc.id` and `vendor.modem.soc_id` (128-bit
  hex, unique per device) and `ro.boot.cdt_hwid`. Redacted to `REDACTED-ID-n`.
- `cache_key.*` values change every boot; `partition.*.verified.root_digest` and
  `ro.boot.vbmeta.*digest` are per build.

## `date` (toybox)

- `date +%s` gives the epoch; `date +%Y-%m-%dT%H:%M:%S%z` gives local time with a
  `-0500` style offset (no colon). They are separate commands, ~100 ms apart.
- The manifest records host UTC before and after each command, bounding the
  device/host clock skew.
- `redact-fixture` rewrites the local line as the same instant at `+0000`, so
  real fixtures always look like a UTC device; `tests/fixtures/synthetic-0930/`
  covers non-zero offsets. Future dumpsys fixtures that print local wall-clock
  times without an offset will need the same shift to stay consistent.

## `pm list packages` (Android 17, Pixel 11 Pro: `tests/fixtures/17-google/capture-1/pm-list-packages-*.txt`)

- `-3 -i` lines are `package:<name>  installer=<pkg>`, with **two spaces** before
  `installer=`. The installer is `null` when nothing recorded one (e.g. `adb
  install`); an APK opened from Files shows `com.google.android.packageinstaller`.
- `-s` lines are just `package:<name>`. The system set includes `android` (a
  one-segment name) and the Verizon/MediaTek services Pixels ship with.
- `-f` prefixes the APK path with `=`; the path itself can contain `=` (the
  `~~base64==` segments), so the name is whatever follows the *last* `=`.
- Output order is not sorted and not stable between calls.

## `pm query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER` (Android 17, Pixel 11 Pro: `capture-5/`)

- One call, ~21 kB / ~0.15 s; one activity per app with an icon on the test phone.
- `<n> activities found:`, then per activity `  Activity #<i>:`, a
  `    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=<bool>`
  line and the component `    <pkg>/<activity>` (`.Main` or a full class name).
- Lists every app with an icon, third-party apps included. `redact-fixture` drops
  a non-allowed app's block whole, renumbers the rest (gaps would show how many
  went) and recounts the header; the component line is a structural position for
  the scanner.
- Platform components (`android`, `com.google.android.gms`,
  `com.google.android.as`) have no launcher activity; Maps, Phone, Chrome do.

## `dumpsys package <pkg>` (Android 17: `dumpsys-package-com.facebook.katana.txt`)

- Top-level sections (no indentation): `Activity Resolver Table:`, `Receiver
  Resolver Table:`, `Service Resolver Table:`, `Domain verification status:`,
  `Permissions:` (repeated), `Registered ContentProviders:`, `ContentProvider
  Authorities:`, `Key Set Manager:`, `Packages:`, `Queries:`, `Dexopt state:`.
- **`Queries:` is device-wide**, even when one package is requested: it is the
  package-visibility graph and names most installed apps. `queriesPackages=[...]`
  is the app's own manifest declaration and can name apps that aren't installed.
  Both go through the package allowlist in `redact-fixture`.
- Per-install values normalised by `redact-fixture`: `timeStamp=`,
  `lastUpdateTime=`, `firstInstallTime=` (-> `2000-01-01 00:00:00`), the random
  `/data/app/~~<base64>==/<pkg>-<base64>==` segments (-> `REDACTED`) and the
  domain-verification `ID: <uuid>`, theme overlay paths
  `/data/resource-cache/<pkg>-<kind>-<4 random>.frro` (-> `XXXX`),
  `ceDataInode=`/`deDataInode=` (-> `0`) and `Signing KeySets: <n>` (-> `1`).
- Object hashes (`Package{f39ba71 …}`, `filter c59f088`) change every boot; kept.
- **What each form includes** (measured on the Pixel 11 Pro, with about a hundred third-party apps):

  | Command | Size | Time | `requested permissions:` | Packages |
  |---|---|---|---|---|
  | `dumpsys package <pkg>` x113 | 5.9 MB | ~11 s | yes | one per call |
  | `dumpsys package packages` | 3.0 MB | ~0.15 s | **no** | all 491 |
  | `dumpsys package` (everything) | 7.5 MB | ~1.9 s | **no** | all 491 |

  Runtime permissions, install permissions, flags, versions, installer and
  per-user state are identical across the three. The per-app form's repeated
  `Queries:` sections are ~7% of its size. Runtime permissions list every
  requested *runtime* permission with its grant state, so requested-only adds
  normal/signature permissions that weren't granted.
- Section dumps end with `Hidden system packages:` (factory versions of updated
  system apps). Not current packages; the parser ignores them.
- **Shared-UID apps:** packages with `sharedUser=SharedUserSetting{<hash> <name>/<uid>}`
  have *no* `runtime permissions:` list in their own block; their grants are
  printed under the shared user in a `Shared users:` section. Per-app dumps include
  that section; `dumpsys package packages` doesn't. On the Pixel 11 Pro several
  packages, system and third-party, use a shared UID. `PackageInfo.shared_user` records it so an
  empty list isn't read as "no permissions".
- **`dumpsys package shared-users`** (130 kB, ~0.05 s; fixture
  `dumpsys-package-shared-users.txt`, trimmed to 3 of 18 entries): one
  `SharedUser [<name>] (<hash>):` entry per shared UID with `appId=`, a
  `Packages` list (no colon) of `PackageSetting{<hash> <pkg>/<uid>}`, `install
  permissions:`, and `User <n>: ` (trailing space) with `runtime permissions:`.
  The shared-user *name* isn't a package name and can identify the vendor, so
  `redact-fixture` drops a whole entry if any member isn't system or allowlisted.
  Only the long form is allowlisted; the `s` alias and `noperm` are refused.
- `installerPackageName=null` means no installer was recorded (e.g. the package
  installer itself, factory copies); it is not a package name.
- Permission names in grant lists can carry an owner prefix:
  `<owner package>#<permission>`, e.g.
  `com.example.owner#com.example.provider.ACCESS_DATA` (seen in a system app's grants).
- Kept, because the rules need them: runtime permission grants and flags
  (`USER_SET`, `USER_FIXED`, ...), enabled/disabled components, version, uids.

## `dumpsys appops` (Android 17, Pixel 11 Pro)

- One call: ~2 MB, ~0.25 s, every app. `cmd appops get <pkg>` x113 takes ~8 s and
  only gives modes. `dumpsys appops --history` (~10 kB) is aggregated counts.
- Top-level sections: `AppOps Service state:`, `AppOps Restrictions`,
  `Historical restrictions`, `AppOps Uid Op State` (the bulk), then `History:`
  with a pipe-delimited **"Location, Microphone, and Camera App Ops (Last 1
  Hour)"** table: `UID|PACKAGE_NAME|DEVICE_ID|OP_NAME|ATTRIBUTION_TAG|ACCESS_TIME|
  ACCESS_COUNTS|REJECT_COUNTS|DURATION|UID_STATE|OP_FLAGS|ATTRIBUTION_CHAIN_ID|
  ATTRIBUTION_FLAGS`, with access *and reject counts* per UID state.
- Per-UID block `  Uid u0a426:` (user 0, app id 10426; system UIDs are plain
  numbers like `1000`): `state=`, `capability=`, then UID-level modes as
  `      OP: mode=<mode>` (the effective policy), then `    Package <pkg>:` members.
- Per-package op: `      OP (<mode>):` or `      OP (<mode> / switch OTHER_OP=<mode>):`,
  then one group per attribution tag (`null=[` ... `]`), with one line per UID
  state: `Access: [top-s] <local time> (<relative>)[ duration=+...][ proxy[uid=N,
  pkg=<pkg>, attributionTag=<tag>]]`. **`Reject:` has no space after `]`**:
  `Reject: [bg-s]2027-11-12 08:52:30.400 (...)`.
- UID states seen: `top`, `fg`, `fgsvc`, `bg`, `cch` (cached: the process is kept
  in memory but not running anything the user can see, e.g. an app recently
  closed), `pers` (persistent system process).
  Attribution suffixes: `s`, `tp`, `tpd`, `up`, `upd`.
- Times are device-local wall clock without an offset; relative parts change on
  every call.
- **`Historical restrictions`** lists Do Not Disturb / Bedtime changes with a
  **year-less** time and colon milliseconds: `11-11 23:10:00:250 op: PLAY_AUDIO,
  usage: ...: Restriction[mode: ignore, exceptions: [<pkg>, ...]]`. It reveals
  the owner's sleep schedule; `redact-fixture` shifts these times (year taken from
  the capture) and filters the `exceptions: [...]` package list.
- **Secondary UID for one package:** `com.google.android.as` (Android System
  Intelligence, app id 10168) has two UID blocks: `u0a168` (UID 10168) and
  `u0a20168`, which the 1-hour table calls UID **30168** (`uXaN` means app id
  10000 + N). Evidence, checked by hand on the Pixel 11 Pro: `ps` shows UID 30168
  running a process named `com.google.android.as`, and `pm list packages -U`
  shows no package owning 30168. So it is a secondary UID of Android System
  Intelligence, not a separate app. **Role unconfirmed**: likely an isolated
  Private Compute Core process. appopsy doesn't infer this from the number
  (no "+20000" rule): `link_uids()` marks a UID secondary when its app id differs
  from the package's own `appId` in `dumpsys package packages`, and reports label
  it "<package> (secondary UID <uid>)". `ps` is not on the allowlist and isn't
  needed for this.
- **Running ops:** a line `Running start at: +13h49m29s269ms` after an op's events
  means the op is still in progress, started that long before the dump (it
  matches the last Access line's relative time). Parsed as `PackageOp.running_for`.
  When the op was started more than once without finishing, `startNesting=<n>`
  follows (`PackageOp.running_nesting`).
- **Location op categories:** `FINE_LOCATION` / `COARSE_LOCATION` Access/Reject
  lines are the evidence that a location was delivered or denied.
  `MONITOR_LOCATION` / `MONITOR_HIGH_POWER_LOCATION` record an active location
  *request* (often `(allow / switch COARSE_LOCATION=allow)`), and `GPS` that the GPS
  engine ran for the app. A `MONITOR_LOCATION` Access in `[bg-s]` is **not** a
  location received in the background: in capture-1, Facebook has exactly that
  (`duration=+3ms`) while all its background FINE/COARSE events are rejects.
- `AppOps Service state:` lists location / activity-recognition provider tags per
  UID (`#0: 10309=<pkg>[tag, ...]`).
- Where other apps appear (structural positions for the package policy):
  `Package <pkg>:` inside UID blocks, the table's `PACKAGE_NAME` column, and
  `proxy[..., pkg=<pkg>, ...]`. `redact-fixture` drops a whole UID block if any
  member isn't system or allowlisted, since its op history still points at the app.

## `dumpsys jobscheduler` (Android 17, Pixel 11 Pro: `capture-2/`)

- One call, ~3.6 MB / ~0.25 s. Top-level sections: settings and battery state,
  `CountQuotaTracker:`, `Registered <n> jobs:`, the controllers (`Prefetch`,
  `Flexibility`, `Connectivity`, `Time`, `Idle`, `Battery`, `Storage`,
  `BackgroundJobs`, `Component`), `Uid proc states:`, `Cached UID->package map:`,
  `Historical stats at <YYYY-MM-DD-HH-MM-SS>` / `Current stats at ...`,
  `Pending queue:`, `Active jobs:`, `Recently completed jobs:`, `Concurrency:`.
- Job headers come in two forms: `JOB #u0a426/<id>: <hash> <pkg>/<service>` and,
  for WorkManager, `JOB androidx.work.systemjobscheduler:u0a426/<id>: <hash>
  #<Worker>#@androidx.work.systemjobscheduler@<pkg>/androidx.work...`. The worker
  class is also in `Trace tag: <Worker>`.
- `Recently completed jobs:` entries are a relative-time line (`  -1m14s674ms`)
  with the job's lines as more-indented siblings. The job line is
  `<hash> {<namespace>} #<label>/<id> <target>`, but jobs outside a namespace
  print no `{...}` at all: `<hash> #u0aN/1 <pkg>/<service>` (seen on a full capture-4 dump).
- Dashed time `YYYY-MM-DD-HH-MM-SS` appears only in the stats headers. Ten-digit
  numbers like `##u0aN/-17...` are job IDs, not epochs.
- Job `Extras: {...}` bundles are app-defined (sync jobs carry `accountName`);
  WorkManager jobs show only `Extras: mParcelledData.dataSize=<n>`.
- A job's `Network type: NetworkRequest [ ... Capabilities: ... ]` says which
  network it needs. `redact-fixture` keeps only the class: `Network type:
  unmetered` (the request includes `NOT_METERED`) or `Network type: any`, because
  `unconstrained-background-work` needs it and the rest can reveal VPN use.
  capture-2 and capture-3 predate this, so their network jobs parse as
  `network="unknown"` and can't be classed as unconstrained or not.
- `redact-fixture`: other network details (ConnectivityController body,
  `NetworkRequest [...]` elsewhere, `Network: <id>`, `CNM{... Transports ...}`) are dropped,
  non-empty extras become `{REDACTED}`, job IDs get capture-scoped placeholders,
  and job blocks / completed entries of non-allowed apps go whole.
- UID labels can also be `u0pN` (seen in FlexibilityController); its numbering
  isn't known, so it is treated as an unknown UID.

## `dumpsys alarm` (Android 17, Pixel 11 Pro: `capture-2/`)

- One call, ~180 kB / ~0.1 s, one top-level section. Pending alarms are
  `<TYPE> #N: Alarm{<hash> type N origWhen <epoch ms> whenElapsed N <pkg>}` with
  `tag=`, `type=... origWhen=<local time>`, `policyWhenElapsed:` and
  `operation=PendingIntent{...}` lines under them.
- Per-app wakeup stats: `  u0aN:<pkg> +<dur> running, <n> wakeups:` with the alarm
  tags under it (Facebook: `*walarm*:WakingExecutorService.ACTION_ALARM.
  com.facebook.katana.Mqtt_Wakeup`). Tags are intent actions or component names,
  not package names. Each tag is an entry line, `    +<dur> <n> wakes <n> alarms,
  last -<dur>:`, then the tag. A zero running time is printed as `0`, not `+0ms`
  (`    0 1 wakes 1 alarms, ...`), in headers and entries alike.
- On a full dump (capture-4) every header's `<n> wakeups` equals the sum
  of its entries' wakes, so it describes what is listed: `redact-fixture` re-sums
  it after trimming. Trimming or redaction can remove the tag line under an entry
  (e.g. one naming a non-allowed app), so in fixtures the parsed tags can add up to less than
  the header; the header is what `chatty-wakeups` uses.
- Cancelled-alarm history is grouped under **bare UID headers** (`    u0a426:`), so
  the owner is only known through the UID. `redact-fixture` keeps such a block only
  if the capture shows every package of that UID is system or allowlisted.
- Alarms are scheduled ahead (149 days seen), and one was set ~100 years out as a
  "never" placeholder, so the CI time window allows future times.

## `dumpsys location` (Android 17, Pixel 11 Pro: `capture-3/`)

- One call, ~77 kB / ~0.15 s. Under `Location Manager State:`: `User Info:`,
  `Location Settings:` (allow/deny and emergency-bypass package lists, one
  package per line, `[*]` suffix), `Location Providers:` (per provider: state,
  listeners, `last location=Location[...]`), `Historical Aggregate Location
  Provider Data:` (`<uid>/<pkg>[tag]: min/max interval = ..., total/active/
  foreground duration = ..., locations = N`), the GNSS-measurement aggregate,
  `GNSS Manager:` (capabilities, hardware model, metrics), `Geofence Manager:`,
  and `Event Log:`.
- `Location[<provider> <lat>,<lon> hAcc= et= alt= mslAlt= vel= bear= ... {Bundle[...]}]`:
  the record can contain nested brackets, and also appears inside listener
  requests (`... last location=Location[...]}]`). `redact-fixture` replaces each
  record whole with `Location[<provider> REDACTED]`.
- Event log lines: `MM-DD HH:MM:SS.mmm: <provider> provider ...` (year-less, dot
  milliseconds, followed by a colon). Deliveries print only a count:
  `delivered location[N] to <uid>/<pkg>[tag]/<id>`; no location values were seen
  in them. Requests carry `WorkSource{<uid> <pkg>, ...}`.
- `Geofence Manager:` was `service: unregistered` on this device; any entries under
  it are dropped by `redact-fixture` (they can encode home or work).
- GNSS metrics (`Position accuracy mean (m): 12.3...`, TTFF) are single values,
  not coordinates; the coordinate scan only flags pairs and labelled lat/lon.

## getprop: more per-device values

- `com.google.android.setupwizard.complianceDate` is a date well before the build
  date (likely when the phone was set up): normalised to `2000-01-01`.
- Some property *names* carry the carrier ID:
  `setupwizard.feature.<name>.carrier<N>`. Normalised to `carrier0`.
