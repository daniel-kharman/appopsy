# Fixtures

Redacted raw output from real devices. Each real fixture is **one capture
folder**: `<android-version>-<oem>/<capture>/`, holding files from a single
`appopsy audit` run, including that run's `date-epoch.txt`, `date-local.txt`,
`pm-list-packages-3p.txt` and `pm-list-packages-system.txt`. Every file was
produced by `appopsy redact-fixture` and reviewed by hand. Folders named
`synthetic-*` are hand-written, not captured from a device.

**Time.** Every timestamp in a capture is shifted by one constant so the capture
happens at **2030-01-01T00:00:00Z** (`ANCHOR` in `appopsy/redact_time.py`), and written in UTC: the date files sit on
that anchor, and access/reject times, boot times and Do Not Disturb changes keep
their spacing relative to it. Timezone becomes `Etc/UTC` and locale `en-US`.
Install/update times are normalised to midnight on 2000-01-01; build dates and
the security patch level are kept, and fall before the anchor. `synthetic-0930/` is the anchor instant seen from UTC+09:30, so time
conversion with a non-zero offset is still tested.

**Packages.** System packages are kept as they are. The only third-party
packages allowed in any fixture are `com.twitter.android`,
`com.facebook.katana`, `com.facebook.orca`, `com.whatsapp`, `com.tencent.mm` and
the synthetic `com.example.sideloaded` (installed by
`com.google.android.packageinstaller`, i.e. not from Play). `redact-fixture`
enforces this (`--packages FILE` to use another list) and CI fails on any other
third-party package.

`tests/test_fixtures_clean.py` fails CI if an identifier, an unshifted time or a
disallowed package slips through, or if a capture folder lacks its date files
or package lists.

| Folder | Device | Files |
|---|---|---|
| `17-google/capture-1/` | Pixel 11 Pro, Android 17 (SDK 37), patch 2026-10-05 | `getprop.txt`, `date-*.txt`, `pm-list-packages-{3p,system}.txt` (whole); `dumpsys-package-com.facebook.katana.txt` (whole, per-app form, the only one with `requested permissions:`); `dumpsys-package-packages.txt` **trimmed** to the 5 allowlisted apps, `com.android.vending`, `com.google.android.packageinstaller`, `com.google.android.dialer`, `com.google.android.as`, shared-UID `com.google.android.apps.maps`, and Play's `Hidden system packages:` entry; `dumpsys-package-shared-users.txt` **trimmed** to `android.media`, `android.uid.se`, `com.google.android.apps.maps`; `dumpsys-appops.txt` with all header sections and the UID blocks and 1-hour table rows of Facebook (bg/cch location rejects), `com.google.android.as` (app and SDK-sandbox UID), Maps, and the Dialer (GET_ACCOUNTS proxied through `com.google.android.gms`) |
| `17-google/capture-2/` | Same device, later run with the jobscheduler and alarm collectors | all collectors; `dumpsys-jobscheduler.txt` **trimmed** to every Facebook job (WorkManager: IdentityHashWorker, StoryTrayPredictionPrefetchWorker, MediaCountUploadWorker, NewsFeedCacheInvalidationWorker, and more) plus a few system jobs, with controller/stats lines for the kept apps; `dumpsys-alarm.txt` trimmed the same way (Facebook and Messenger `Mqtt_Wakeup` alarms, wakeup stats, cancelled-alarm history); package and appops files trimmed as in capture-1 |
| `17-google/capture-3/` | Same device, later run with the location collector | all collectors; `dumpsys-location.txt` **whole** (every location record replaced whole, event log shifted, other apps removed); the other files trimmed as in capture-2 |
| `17-google/capture-4/` | Same device, run after redaction kept each job's network class | all collectors; every job of the allowlisted apps with `Network type: unmetered/any` (no undetermined network jobs); appops UID blocks for all five allowlisted apps plus as, Maps and dialer; the other files trimmed as in capture-3 |
| `17-google/capture-5/` | Same device, first run with the launcher query | all collectors; `pm-query-launcher.txt` with the 5 allowlisted apps and every system app's launcher activity (other apps dropped whole, renumbered, total recounted); the other files trimmed as in capture-4 |
| `synthetic-0930/` | Synthetic: the anchor instant at UTC+09:30 | `date-epoch.txt`, `date-local.txt` |
