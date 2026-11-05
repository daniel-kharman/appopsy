# Rule ideas

Candidate rules that aren't built yet. Each needs a pack, a severity on that
pack's scale, and the usual what / why / benign / remediation text before it
becomes a YAML file in `rules/`.

## `location-history-from-media` (privacy)

**Idea:** an app holding *all three* of the following "can reconstruct your
location history":

1. **Full media access**: `READ_MEDIA_IMAGES` (and/or `READ_MEDIA_VIDEO`) granted.
   Not the partial "Select photos" grant, which shows up as
   `READ_MEDIA_VISUAL_USER_SELECTED` granted with `READ_MEDIA_IMAGES` denied. On
   older target SDKs, `READ_EXTERNAL_STORAGE` or `MANAGE_EXTERNAL_STORAGE` count.
2. **`ACCESS_MEDIA_LOCATION`** granted: without it Android strips GPS
   coordinates from the photos the app reads.
3. **`ACCESS_BACKGROUND_LOCATION`** granted: where you are now, not only while the
   app is open.

Why it matters: photo EXIF coordinates cover where you've been for as long as you've had
the photos; background location covers where you are going. Together that's
a location history, possibly years long, built without any single permission
looking alarming.

- **Pack / severity:** privacy, probably `concern` when all three hold and
  `notable` for (1) + (2) alone (past locations only).
- **Data:** runtime permission grants from `dumpsys package packages`, following
  shared UIDs via `runtime_permissions_for()`. Then check the matching appops
  modes (`READ_MEDIA_IMAGES`, `ACCESS_MEDIA_LOCATION`, `FINE_LOCATION`/
  `COARSE_LOCATION` in background) before saying "can". A granted permission
  whose op is `ignore` doesn't actually allow access. That gap between grant
  and mode is why the two are modelled separately.
- **Benign explanations:** gallery, maps and travel apps use this legitimately
  (showing photos on a map, timeline features).
- **Remediation:** switch photos to "Allow limited access" / "Select photos",
  turn off "Access media location" if the app offers it, or set location to
  "Only while using the app".
- **Test case already in the fixtures:** `com.google.android.apps.maps` in
  `tests/fixtures/17-google/capture-1/dumpsys-package-shared-users.txt` has
  `READ_MEDIA_IMAGES`, `ACCESS_MEDIA_LOCATION` and `ACCESS_BACKGROUND_LOCATION`
  all granted (via its shared UID). It's a system app, so the rule should decide
  whether system apps are in scope or reported separately.

## `security-patch-age` (security)

**Idea:** report how old the device's security patch is, from
`ro.build.version.security_patch` (and `ro.vendor.build.security_patch`, which can
lag behind it), measured against the device clock at capture time.

- **Pack / severity:** security, since an old patch is exposure rather than an
  app's behaviour. Suggested scale: under 3 months `low`/no finding, 3–6 months
  `medium`, over 6 months, or a platform/vendor gap over 3 months, `high`. Never
  `critical` on its own: it says the phone is exposed, not that it's compromised.
- **Data:** `getprop` patch levels and `date-epoch.txt`. A device that has stopped
  receiving updates (end of support) is the case worth explaining in plain words.
- **Benign explanations:** the update is downloaded but waiting for a reboot;
  carriers and OEMs roll out monthly patches weeks late.
- **Remediation:** Settings > System > Software updates (and Google Play system
  update); if the device is out of support, say so and what that means.
- **Fixtures:** shifted captures sit on the 2030-01-01 anchor, after every real
  patch date (that's why the anchor is 2030), so ages computed from fixtures are
  positive but inflated (capture-1: 2026-10-05 → about 3 years 3 months). Tests
  must compute expected ages from `ANCHOR`, never from today's date.

## Framing: system apps vs user-installed apps (all privacy rules)

**Principle for the rules stage:** the report must not flag the OS itself as a
privacy concern at the same level as an app the user chose to install.

Example from `capture-3`: `com.google.android.as` (Android System Intelligence,
a system app, under its primary UID and a secondary UID) holds location requests
at a 6-hour interval that stay active for 11–15 hours. In absolute terms that's a
long-running background location request, but it's the platform's own
on-device-intelligence service, not a third-party app. Facebook's short requests
and repeated background rejects are a different kind of finding.

- **Classify first:** user-installed (from `pm list packages -3`), preinstalled
  but updatable, and system/platform (the `SYSTEM` flag, `android`, platform UIDs
  below 10000, shared system UIDs). Secondary UIDs inherit their package's class.
- **Separate framing, not silence:** system-app behaviour is still shown (it's
  real, and some users want to know), but in its own section ("What the system
  itself does"), at `info`, with explanation of what the component is and how to
  turn it off if Android offers a setting. It must not be ranked alongside, or
  share a severity label with, user-installed apps.
- **No severity escalation for system apps** from `notable` / `concern` rules;
  their counterpart is informational. A rule that *does* apply to system apps on
  purpose (e.g. a security-pack check for a tampered or sideloaded "system" app)
  says so explicitly.
- **Preinstalled third-party apps** (OEM or carrier bundles, e.g. the Verizon
  services every Pixel ships) are a grey area: treat as user-facing apps the user
  didn't choose, and say that ("came with the phone").
- **Tests:** capture-3 gives both sides: `com.google.android.as` must land in the
  system section at `info`; Facebook's background attempts in the main findings.
