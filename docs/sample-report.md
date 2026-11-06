# appopsy report: Pixel 11 Pro

Google Pixel 11 Pro, Android 17 (SDK 37), security patch 2026-10-05.
Collected on a date not shown in this copy, with appopsy 0.1.0.dev0.

> **Redacted copy for sharing.** Every app in it is a system app or a well-known
> app, so all keep their names. Times are shown as days before collection. Check it
> before you share it.

Google Maps received your location while not on screen. Facebook, WeChat and WhatsApp tried to use your location in the background and were refused, because your settings allow it only while the app is in use. Facebook (14) and Messenger (3) have background jobs that can run on battery and mobile data at any time, 17 in all. Google Maps, which came with the phone, has the broadest access: 6 of the 9 kinds of sensitive access appopsy checks, including your precise location, contacts, photos and videos at any time.

This report says what the apps on this phone are allowed to do, what Android
recorded them doing, and what they tried to do and were refused. appopsy only
reads: nothing on the phone was changed. Each finding says what was seen, why it
may matter, what is probably harmless about it, and what you can do.

## Summary

| Privacy findings | Count |
|---|---:|
| Concern | 0 |
| Notable | 6 |
| Info | 11 |
| System components (listed separately) | 13 |

7 apps have findings; [Per-app detail](#per-app-detail) lists them, most severe first.

## Privacy findings

### Notable

#### Tried to use a sensor in the background and was refused

Android recorded the app trying to use location, the camera, the microphone or body sensors while it was in the background, at a time when it was only allowed to use them in the foreground (or not at all), and refused it.

**Why it matters:** The attempt shows the app wanted sensor data while you weren't using it. Your setting worked, but the app kept trying: repeated refused attempts can mean it is built to collect data in the background where it is allowed to.

**Facebook (com.facebook.katana)** tried to use your location in the background, where it isn't allowed, and was refused.

| Sensor | Setting | Refused while | Last refused |
|---|---|---|---|
| precise location (FINE_LOCATION) | only while in use | in the background, cached in the background | yesterday |
| approximate location (COARSE_LOCATION) | only while in use | in the background, cached in the background | yesterday |

Evidence: dumpsys-appops.txt: lines 916, 917, 969, 970, 976, 977

**WeChat (com.tencent.mm)** tried to use your precise location in the background, where it isn't allowed, and was refused.

| Sensor | Setting | Refused while | Last refused |
|---|---|---|---|
| precise location (FINE_LOCATION) | only while in use | in the background | 2 days ago |

Evidence: dumpsys-appops.txt: lines 639, 691

**WhatsApp (com.whatsapp)** tried to use your approximate location in the background, where it isn't allowed, and was refused.

| Sensor | Setting | Refused while | Last refused |
|---|---|---|---|
| approximate location (COARSE_LOCATION) | only while in use | in the background, cached in the background | 4 days ago |

Evidence: dumpsys-appops.txt: lines 1086, 1132, 1133

**Probably harmless:**

- Some apps ask for location when they start or resume and are briefly classed as background while doing so.
- A feature you enabled (location sharing, check-ins, nearby friends) may try to run in the background.
- Libraries inside the app (ads, analytics, maps) can make the request without the app's own features needing it.

#### Used a sensor while not on screen

Android allowed the app to use location, the camera, the microphone or body sensors while it wasn't on screen: in the background, or from a foreground service (which shows a notification while it runs). These are deliveries the app received, not requests it made. Camera or microphone use in the background proper is a concern; from a foreground service only, Android shows a notification and the privacy indicator while it happens, so it's notable.

**Why it matters:** This is sensor data actually collected while you weren't looking at the app. The microphone and camera matter most: they can capture what's around you. Background location builds a record of where you go.

**Google Maps (com.google.android.apps.maps)** used your precise location while it wasn't on screen (in the background and from a foreground service), and Android allowed it.

| Sensor | Setting | Used while | Last used |
|---|---|---|---|
| precise location (FINE_LOCATION) | at any time | in the background, cached in the background, foreground service | yesterday |

Evidence: dumpsys-appops.txt: lines 479, 482, 484

**Probably harmless:**

- Navigation keeps using location from a foreground service while the screen is off or another app is open.
- Call and voice-message apps use the microphone from a foreground service during a call or recording.
- Features you turned on (location sharing, location history, fitness tracking) use sensors in the background by design.

#### Background work that can run at any time

The app has scheduled jobs that require neither charging, nor the phone being idle, nor an unmetered (Wi-Fi) network. They can run whenever the system lets them, on battery and on mobile data. "Any network" is not counted as a constraint. The report lists what each job does require.

**Why it matters:** Background jobs are how apps prefetch content, upload data and report analytics while you aren't using them. Jobs tied to charging, idle or Wi-Fi run when it costs you least; jobs without those conditions can use battery and mobile data at any time.

One row per app, with up to three of its jobs. Details: [appendix](#background-jobs).

| App | Jobs | Includes |
|---|---|---|
| Facebook (com.facebook.katana) | 14 | IdentityHashWorker, OfflineFeedBackgroundPrefetchWorker, NotificationsPermissionWorker, ... |
| Messenger (com.facebook.orca) | 3 | EarlyAccessSyncWorker, SimCarrierInfoLogWorker, LollipopUploadService |

**Probably harmless:**

- Some work is time-sensitive (delivering a message you sent, a backup you asked for) and shouldn't wait for charging.
- A job may run rarely; being able to run at any time doesn't mean it runs often.
- Jobs still have to wait for Doze and battery-saver windows, so "any time" is an upper bound.

### Info

#### Sensitive access each app is allowed

A ranking of apps by how many of nine kinds of sensitive access Android currently allows them: location, camera, microphone, contacts, call log, text messages, photos and videos, body sensors, and running in the background. For each it shows whether the app may use it at any time or only while in use, and whether the access is full or partial (precise or only approximate location; the whole photo library or only selected photos). Selected photos only is the privacy-friendly choice and isn't counted. Every app you installed is listed, even with nothing allowed; apps that came with the phone are ranked with them; platform components are ranked separately.

**Why it matters:** Permissions granted once are easy to forget. Seeing which apps hold the most sensitive access, and which can use it at any time, shows where narrowing a permission makes the most difference.

Ranked by kinds of access, then how many at any time. Each app allowed something at any time has a full entry. Details: [appendix](#sensitive-access-at-any-time).

| App | Kinds of access | At any time |
|---|---|---|
| Google Maps (com.google.android.apps.maps) | 6: location, camera, microphone, contacts, photos and videos, running in the background | 3 |
| WhatsApp (com.whatsapp) | 5: location, camera, microphone, contacts, photos and videos | 2 |
| Phone (com.google.android.dialer) | 4: camera, microphone, contacts, call log | 2 |
| Facebook (com.facebook.katana) | 2: location, camera | — |
| Messenger (com.facebook.orca) | 2: camera, microphone | — |
| WeChat (com.tencent.mm) | 1: location | — |
| X (com.twitter.android) | none | — |

**Probably harmless:**

- Messaging, camera, maps and phone apps need several of these to do their job.
- Being allowed an operation doesn't mean the app uses it; see the sensor-use summary for what happened.
- Approximate location only and selected photos only are partial access; selected photos only isn't counted at all.

#### Recent use of location, camera and microphone

Which apps recently used location, the camera or the microphone, in which state (foreground, foreground service, background), for how long, and how long each app held location requests. Location requests that Android hides from the app-operations record are listed in the system section.

**Why it matters:** Settings shows whether an app is allowed to use a sensor; this shows what it actually did, so you can compare the two.

One row per app; each use, by sensor and state, is listed. Details: [appendix](#recent-sensor-use).

| App | Used | Last used | Longest location request |
|---|---|---|---|
| Facebook (com.facebook.katana) | your location | yesterday | — |
| Google Maps (com.google.android.apps.maps) | your precise location, plus the camera and the microphone | yesterday | 3:37:19 |
| WhatsApp (com.whatsapp) | your location, plus the camera and the microphone | yesterday | — |

**Probably harmless:**

- Navigation, camera, video-call and voice apps use these sensors as their main job.
- System services (location, assistant, emergency features) use location continuously by design.

#### Background work that can run at any time

The app has scheduled jobs that require neither charging, nor the phone being idle, nor an unmetered (Wi-Fi) network. They can run whenever the system lets them, on battery and on mobile data. "Any network" is not counted as a constraint. The report lists what each job does require.

**Why it matters:** Background jobs are how apps prefetch content, upload data and report analytics while you aren't using them. Jobs tied to charging, idle or Wi-Fi run when it costs you least; jobs without those conditions can use battery and mobile data at any time.

These apps came with the phone; most of their jobs come from shared Google libraries. Details: [appendix](#background-jobs).

| App | Jobs |
|---|---|
| Google Maps (com.google.android.apps.maps) | 1 |

**Probably harmless:**

- Some work is time-sensitive (delivering a message you sent, a backup you asked for) and shouldn't wait for charging.
- A job may run rarely; being able to run at any time doesn't mean it runs often.
- Jobs still have to wait for Doze and battery-saver windows, so "any time" is an upper bound.

## Per-app detail

- **Facebook (com.facebook.katana)**, Google Play: [Tried to use a sensor in the background and was refused](#tried-to-use-a-sensor-in-the-background-and-was-refused) (notable); [Background work that can run at any time](#background-work-that-can-run-at-any-time) (notable); [Sensitive access each app is allowed](#sensitive-access-each-app-is-allowed) (info); [Recent use of location, camera and microphone](#recent-use-of-location-camera-and-microphone) (info)
- **Google Maps (com.google.android.apps.maps)**, came with the phone: [Used a sensor while not on screen](#used-a-sensor-while-not-on-screen) (notable); [Sensitive access each app is allowed](#sensitive-access-each-app-is-allowed) (info); [Recent use of location, camera and microphone](#recent-use-of-location-camera-and-microphone) (info); [Background work that can run at any time](#background-work-that-can-run-at-any-time-1) (info)
- **WhatsApp (com.whatsapp)**, Google Play: [Tried to use a sensor in the background and was refused](#tried-to-use-a-sensor-in-the-background-and-was-refused) (notable); [Sensitive access each app is allowed](#sensitive-access-each-app-is-allowed) (info); [Recent use of location, camera and microphone](#recent-use-of-location-camera-and-microphone) (info)
- **Messenger (com.facebook.orca)**, Google Play: [Background work that can run at any time](#background-work-that-can-run-at-any-time) (notable); [Sensitive access each app is allowed](#sensitive-access-each-app-is-allowed) (info)
- **WeChat (com.tencent.mm)**, Google Play: [Tried to use a sensor in the background and was refused](#tried-to-use-a-sensor-in-the-background-and-was-refused) (notable); [Sensitive access each app is allowed](#sensitive-access-each-app-is-allowed) (info)
- **Phone (com.google.android.dialer)**, came with the phone: [Sensitive access each app is allowed](#sensitive-access-each-app-is-allowed) (info)
- **X (com.twitter.android)**, Google Play: [Sensitive access each app is allowed](#sensitive-access-each-app-is-allowed) (info)

## What you can do

### Tried to use a sensor in the background and was refused

- Facebook: Settings > Apps > Facebook > Permissions > Location: choose “Don't allow” if you don't use the features that need it.
- WeChat: Settings > Apps > WeChat > Permissions > Location: choose “Don't allow” if you don't use the features that need it.
- WhatsApp: Settings > Apps > WhatsApp > Permissions > Location: choose “Don't allow” if you don't use the features that need it.

In general:

- Keep the permission at "Only while using the app" (Settings > Apps > (the app) > Permissions).
- Turn off the feature that needs background access if you don't use it.
- If the attempts continue, set the app's battery use to Restricted.

### Used a sensor while not on screen

- Google Maps: Settings > Apps > Google Maps > Permissions: set Location to “Allow only while using the app”. Use from a foreground service you start (such as navigation) keeps working.

In general:

- Settings > Apps > (the app) > Permissions > Location: choose "Allow only while using the app".
- Settings > Apps > (the app) > Permissions > Microphone or Camera: choose "Ask every time" or "Don't allow".
- Settings > Security & privacy > Privacy > Privacy dashboard shows when each app used them in the last 24 hours.

### Background work that can run at any time

- Settings > Apps > (the app) > App battery usage: choose Restricted to defer its background jobs. Apps and their jobs: Facebook (14), Messenger (3).

In general:

- Settings > Apps > (the app) > App battery usage: choose Restricted, which defers most background jobs.
- Settings > Apps > (the app) > Mobile data: turn off Background data to keep jobs to Wi-Fi.

### Sensitive access each app is allowed

- Google Maps: Settings > Apps > Google Maps > Permissions: set Location to “Allow only while using the app”; set Contacts to “Don't allow” if it doesn't need them; set Photos and videos to “Allow limited access”.
- WhatsApp: Settings > Apps > WhatsApp > Permissions: set Photos and videos to “Allow limited access”.

In general:

- Settings > Security & privacy > Privacy > Permission manager lists every app per permission.
- Change access the app doesn't need to "Only while using the app", "Ask every time" or "Don't allow".

### Recent use of location, camera and microphone

- Settings > Security & privacy > Privacy > Privacy dashboard shows the same use over the last 24 hours.
- Narrow a permission to "Only while using the app" or "Ask every time" if the use surprises you.

## System components

These packages are part of Android itself and have no app icon. Findings about
them are listed for completeness at the lowest level of their scale and are not
counted with the apps above. They can't be uninstalled, and most can't be
restricted. Apps that came with the phone and have an icon (such as Maps) are
listed with your other apps above.

| Finding | Components |
|---|---|
| Used a sensor while not on screen | 1: Android System Intelligence (com.google.android.as, secondary UID 30168) |
| Wakes the phone often | 1: Google Play services (com.google.android.gms) |
| Sensitive access each app is allowed | 1: Android System Intelligence (com.google.android.as) |
| Recent use of location, camera and microphone | 6: Android system (android), com.android.imsstack, Fused location provider (com.android.location.fused), Phone services (com.android.phone) and 2 more |
| Background work that can run at any time | 2: Android system (android) and Android System Intelligence (com.google.android.as) |

- **Google Play services (com.google.android.gms)**: Play services delivers push notifications and runs sync for many apps, so its wake-ups stand in for many apps at once. Android doesn't let you restrict it.

Each finding in full: [appendix](#system-components-1).

## How this report was made

- **Tried to use a sensor in the background and was refused** (`background-sensor-attempt`, privacy, notable).
- **Used a sensor while not on screen** (`background-sensor-use`, privacy, notable).
  No threshold: No threshold: one background delivery is enough to report. Severity follows the sensor and how visible the use was: concern for the microphone or camera used in the background or cached state (bg, cch), where nothing on screen shows it; notable for the microphone or camera used only from a foreground service (fgsvc), because Android shows the service's notification and the privacy indicator while it runs; notable for location and body sensors in any of these states (body sensors grouped with location by appopsy, not by an external source). Only Access events in the bg, cch and fgsvc states count, for FINE_LOCATION, COARSE_LOCATION, CAMERA, RECORD_AUDIO and BODY_SENSORS; location requests (MONITOR_LOCATION, MONITOR_HIGH_POWER_LOCATION) and GPS never do, because they don't show that anything was delivered.
- **Wakes the phone often** (`chatty-wakeups`, privacy, notable).
  Threshold `wakeups_per_hour`: 10 wakeup alarms (RTC_WAKEUP and ELAPSED_REALTIME_WAKEUP) per hour. Source: [Play Console Help, "Excessive wake-ups" (Android vitals)](https://support.google.com/googleplay/android-developer/answer/7385505), checked 2026-11-01, verified. Android vitals counts more than 10 wake-ups per hour in a battery session, only while the device is not charging, and only ELAPSED_REALTIME_WAKEUP and RTC_WAKEUP alarms. appopsy counts only those two alarm types too, but dumpsys alarm gives a since-boot total, so its rate is wakeups since boot divided by uptime, charging time included. That approximates the battery-session rate and likely understates it.
- **Sensitive access each app is allowed** (`over-privileged-app`, privacy, info).
  No threshold: This rule has no threshold on purpose. There is no published guidance on how many sensitive permissions make an app "over-privileged", so appopsy doesn't pick a number: it ranks apps by the number of kinds of access allowed, then by how many are allowed at any time, then by how many are full rather than partial, and reports every app at `info`. A kind of access counts once however many Android operations sit behind it. Operations the dump doesn't print for an app (e.g. RUN_ANY_IN_BACKGROUND when left at its default) are not counted.
- **Recent use of location, camera and microphone** (`sensor-use-summary`, privacy, info).
- **Background work that can run at any time** (`unconstrained-background-work`, privacy, notable).
  No threshold: Apps you installed are reported at notable. Apps that came with the phone (a system package with a launcher icon) are reported at info: on a typical phone they schedule dozens of such jobs, most from shared Google libraries (the notifications platform, an app framework, account sync), so listing each at notable would bury the apps you chose. The report shows them as one compact table with full job lists in an appendix. Platform components stay in the system section, as for every rule.

Evidence gives line numbers in the files of the case folder's `raw/` directory,
which hold the phone's output exactly as collected.

## Appendix

### Sensitive access at any time

Every app allowed at least one kind of sensitive access at any time, in rank order.

#### Google Maps (com.google.android.apps.maps)

is allowed 6 of the 9 kinds of sensitive access appopsy checks: your precise location, contacts, photos and videos, plus running in the background at any time; the camera and the microphone only while it's in use. It ranks 1 of 7 apps.

| Allowed | When | Scope |
|---|---|---|
| Location (FINE_LOCATION, COARSE_LOCATION) | at any time | precise |
| Camera (CAMERA) | only while in use | — |
| Microphone (RECORD_AUDIO) | only while in use | — |
| Contacts (READ_CONTACTS) | at any time | — |
| Photos and videos (READ_MEDIA_IMAGES, READ_MEDIA_VIDEO, READ_MEDIA_VISUAL_USER_SELECTED) | at any time | whole library |
| Running in the background (RUN_ANY_IN_BACKGROUND) | at any time | — |

#### WhatsApp (com.whatsapp)

is allowed 5 of the 9 kinds of sensitive access appopsy checks: your contacts, photos and videos at any time; your precise location, plus the camera and the microphone only while it's in use. It ranks 2 of 7 apps.

| Allowed | When | Scope |
|---|---|---|
| Location (FINE_LOCATION, COARSE_LOCATION) | only while in use | precise |
| Camera (CAMERA) | only while in use | — |
| Microphone (RECORD_AUDIO) | only while in use | — |
| Contacts (READ_CONTACTS) | at any time | — |
| Photos and videos (READ_MEDIA_IMAGES, READ_MEDIA_VIDEO, READ_MEDIA_VISUAL_USER_SELECTED) | at any time | whole library |

#### Phone (com.google.android.dialer)

is allowed 4 of the 9 kinds of sensitive access appopsy checks: your contacts and call log at any time; the camera and the microphone only while it's in use. It ranks 3 of 7 apps.

| Allowed | When |
|---|---|
| Camera (CAMERA) | only while in use |
| Microphone (RECORD_AUDIO) | only while in use |
| Contacts (READ_CONTACTS) | at any time |
| Call log (READ_CALL_LOG) | at any time |

### Recent sensor use

Each app's recorded uses, by sensor and the state the app was in.

#### Facebook (com.facebook.katana)

| Sensor | App was | Last used |
|---|---|---|
| approximate location (COARSE_LOCATION) | open on screen | yesterday |
| precise location (FINE_LOCATION) | open on screen | yesterday |

#### Google Maps (com.google.android.apps.maps)

| Sensor | App was | Last used | For |
|---|---|---|---|
| precise location (FINE_LOCATION) | open on screen | yesterday | — |
| precise location (FINE_LOCATION) | foreground service | yesterday | — |
| precise location (FINE_LOCATION) | in the foreground | yesterday | — |
| precise location (FINE_LOCATION) | in the background | yesterday | — |
| precise location (FINE_LOCATION) | cached in the background | yesterday | — |
| camera (CAMERA) | open on screen | 13 days ago | 0:00:02 |
| microphone (RECORD_AUDIO) | open on screen | 2 days ago | 0:00:00 |

| Location provider | Requested for | In background | Location fixes delivered |
|---|---|---|---|
| gps | 3:37:19 | 0:00:42 | 10596 |

#### WhatsApp (com.whatsapp)

| Sensor | App was | Last used | For |
|---|---|---|---|
| approximate location (COARSE_LOCATION) | open on screen | 4 days ago | — |
| precise location (FINE_LOCATION) | open on screen | 2 days ago | — |
| camera (CAMERA) | open on screen | yesterday | 0:00:14 |
| microphone (RECORD_AUDIO) | open on screen | 4 days ago | 0:04:20 |

### Background jobs

The full job lists behind the background-work findings.

#### Shared job libraries

Job names that several apps schedule because they come from the same library. Each is listed once here; the apps' tables label them with it.

| Library | Job | Apps | Used by |
|---|---|---|---|
| a library several apps share | SimCarrierInfoLogWorker | 2 | Facebook, Messenger |

#### Facebook (com.facebook.katana)

has 14 background jobs that can run without charging, the phone being idle or Wi-Fi, including IdentityHashWorker, OfflineFeedBackgroundPrefetchWorker, NotificationsPermissionWorker and 11 more.

| Job | Waits only for |
|---|---|
| IdentityHashWorker | any network |
| OfflineFeedBackgroundPrefetchWorker | any network |
| NotificationsPermissionWorker | — |
| StoryTrayPredictionPrefetchWorker | any network |
| MediaCountUploadWorker | any network |
| FeedAdsChannelBackgroundPrefetchWorker | any network |
| FeedBackgroundPrefetchWorker | any network |
| a library several apps share: SimCarrierInfoLogWorker | any network |
| OnDeviceDerivedAppHistoryWorker | any network |
| FFJobService | a deadline, any network |
| FBPapayaJobService | any network |
| LollipopConditionalWorkerService | any network |
| PushNegativeFeedbackLollipopService | any network |
| UpdateLocalMediaStoreJobService | — |

Evidence: dumpsys-jobscheduler.txt: lines 679-716, 717-754, 755-790, 872-909, 910-947, 948-985, 986-1023, 1024-1061 and 6 more

#### Messenger (com.facebook.orca)

has 3 background jobs that can run without charging, the phone being idle or Wi-Fi: EarlyAccessSyncWorker, SimCarrierInfoLogWorker and LollipopUploadService.

| Job | Waits only for |
|---|---|
| EarlyAccessSyncWorker | any network |
| a library several apps share: SimCarrierInfoLogWorker | any network |
| LollipopUploadService | a deadline, any network |

Evidence: dumpsys-jobscheduler.txt: lines 548-590, 591-633, 634-678

#### Google Maps (com.google.android.apps.maps)

has 1 background job that can run without charging, the phone being idle or Wi-Fi: GmmWorkerWrapper.

| Job |
|---|
| GmmWorkerWrapper |

Evidence: dumpsys-jobscheduler.txt: lines 512-547

### System components

Every finding about platform components, at the lowest level of its scale.

#### Android system (android): Recent use of location, camera and microphone

asked for location updates.

| Location provider | Requested for | In background | Location fixes delivered |
|---|---|---|---|
| passive | 1 day, 11:20:01 | 0:00:00 | 1 |
| passive | 1 day, 11:20:01 | 0:00:00 | 1 |
| passive | 0:00:06 | 0:00:00 | 2 |
| gps | 0:00:30 | 0:00:00 | 1 |
| fused | 1 day, 11:20:01 | 0:00:00 | 68 |
| network | 1 day, 11:20:02 | 0:00:00 | 2682 |

Evidence: dumpsys-location.txt: lines 100, 101, 103, 107, 113, 117

#### Android system (android): Recent use of location, camera and microphone

holds 1 location request that Android keeps out of the permission history, so Settings doesn't show them.

| Provider | Requested as |
|---|---|
| network | GnssService |

Evidence: dumpsys-location.txt: line 34

#### Android system (android): Background work that can run at any time

has 1 background job that can run without charging, the phone being idle or Wi-Fi: ReportWidgetEventsJob.

| Job | Waits only for | Repeats every |
|---|---|---|
| ReportWidgetEventsJob | a deadline | 1:00:00 |

Evidence: dumpsys-jobscheduler.txt: lines 261-297

#### Android System Intelligence (com.google.android.as, secondary UID 30168): Used a sensor while not on screen

used your precise location while it wasn't on screen (from a foreground service), and Android allowed it.

| Sensor | Setting | Used while | Last used |
|---|---|---|---|
| precise location (FINE_LOCATION) | at any time | foreground service | yesterday |

Evidence: dumpsys-appops.txt: line 1357

#### Android System Intelligence (com.google.android.as): Sensitive access each app is allowed

is allowed 7 of the 9 kinds of sensitive access appopsy checks: your precise location, contacts, call log, text messages, photos and videos at any time; the camera and the microphone only while it's in use. It ranks 1 of 1 system components.

| Allowed | When | Scope |
|---|---|---|
| Location (FINE_LOCATION, COARSE_LOCATION) | at any time | precise |
| Camera (CAMERA) | only while in use | — |
| Microphone (RECORD_AUDIO) | only while in use | — |
| Contacts (READ_CONTACTS) | at any time | — |
| Call log (READ_CALL_LOG) | at any time | — |
| Text messages (READ_SMS) | at any time | — |
| Photos and videos (READ_MEDIA_IMAGES, READ_MEDIA_VIDEO) | at any time | whole library |

Evidence: dumpsys-appops.txt: lines 121, 122, 151, 152, 157, 163, 168, 176 and 2 more

#### Android System Intelligence (com.google.android.as): Recent use of location, camera and microphone

used your precise location, plus the microphone, and asked for location updates.

| Sensor | App was | Last used |
|---|---|---|
| precise location (FINE_LOCATION) | open on screen | 14 days ago |
| precise location (FINE_LOCATION) | in the foreground | 3 days ago |
| microphone (RECORD_AUDIO) | in the foreground | 4 days ago |
| precise location (FINE_LOCATION) | open on screen | 2 days ago |
| precise location (FINE_LOCATION) | foreground service | yesterday |
| precise location (FINE_LOCATION) | in the foreground | yesterday |

| Location provider | Requested for | In background | Location fixes delivered |
|---|---|---|---|
| network | 1 day, 11:19:57 | 0:00:00 | 1 |

Evidence: dumpsys-appops.txt: lines 154, 155, 178, 1356, 1357, 1358; dumpsys-location.txt: line 118

#### Android System Intelligence (com.google.android.as): Background work that can run at any time

has 1 background job that can run without charging, the phone being idle or Wi-Fi: PeriodicCleanupService.

| Job | Waits only for | Repeats every |
|---|---|---|
| PeriodicCleanupService | a deadline | 1 day, 0:00:00 |

Evidence: dumpsys-jobscheduler.txt: lines 341-382

#### com.android.imsstack: Recent use of location, camera and microphone

asked for location updates.

| Location provider | Requested for | In background | Location fixes delivered |
|---|---|---|---|
| fused | 0:00:06 | 0:00:00 | 6 |

Evidence: dumpsys-location.txt: line 112

#### Fused location provider (com.android.location.fused): Recent use of location, camera and microphone

asked for location updates.

| Location provider | Requested for | In background | Location fixes delivered |
|---|---|---|---|
| gps | 0:00:01 | 0:00:00 | 0 |
| network | 0:00:01 | 0:00:00 | 0 |

Evidence: dumpsys-location.txt: lines 106, 116

#### Google Play services (com.google.android.gms): Wakes the phone often

woke the phone 1018 times in 35.3 hours, 28.8 times an hour on average (the threshold is 10).

| Alarm | Wake-ups |
|---|---|
| \*walarm\*:NetworkLocationActivityDetection | 523 |
| \*walarm\*:com.google.android.gms.gcm.HEARTBEAT_ALARM | 118 |
| \*walarm\*:NetworkLocationScanner | 90 |
| \*walarm\*:FusedLocation:expire | 72 |
| \*walarm\*:FusedLocation:delay_request | 67 |

Evidence: dumpsys-alarm.txt: lines 732-800

#### Google Play services (com.google.android.gms): Recent use of location, camera and microphone

asked for location updates.

| Location provider | Requested for | In background | Location fixes delivered |
|---|---|---|---|
| passive | 1 day, 11:19:58 | 0:00:00 | 83808 |
| passive | 22:57:37 | 0:00:00 | 8851 |
| gps | 3:51:58 | 0:00:00 | 10925 |
| gps | 0:02:48 | 0:00:00 | 139 |
| gps | 3:33:56 | 0:00:00 | 10853 |

Evidence: dumpsys-location.txt: lines 99, 102, 105, 108, 109

#### Google Play services (com.google.android.gms): Recent use of location, camera and microphone

holds 3 location requests that Android keeps out of the permission history, so Settings doesn't show them.

| Provider | Requested as |
|---|---|
| passive | network_location_provider |
| passive | fused_location_provider |
| passive | fused_location_provider |

Evidence: dumpsys-location.txt: lines 21, 24, 25

#### Phone services (com.android.phone): Recent use of location, camera and microphone

asked for location updates.

| Location provider | Requested for | In background | Location fixes delivered |
|---|---|---|---|
| fused | 0:00:04 | 0:00:00 | 1 |

Evidence: dumpsys-location.txt: line 114
