"""Redaction of `dumpsys jobscheduler` and `dumpsys alarm` (synthetic data).

com.example.bank / org.example.* stand in for apps that must not appear in a
fixture; Facebook is on the public allowlist. Times are made up.
"""

from __future__ import annotations

from datetime import UTC, datetime

from appopsy.redact import Redactor, scan

SYSTEM = "package:android\npackage:com.google.android.gms\n"
THIRD_PARTY = (
    "package:com.facebook.katana  installer=com.android.vending\n"
    "package:com.example.bank  installer=com.android.vending\n"
)
CAPTURE_EPOCH = int(datetime(2027, 11, 12, 14, 15, tzinfo=UTC).timestamp())

JOBS = """\
Registered 3 jobs:
  JOB #u0a426/10001: 568bf2b com.facebook.katana/com.facebook.falco.jobscheduler.FFJobService
    u0a426 tag=*job*r/com.facebook.katana/com.facebook.falco.jobscheduler.FFJobService
    Source: uid=u0a426 user=0 pkg=com.facebook.katana
    JobInfo:
      Service: com.facebook.katana/com.facebook.falco.jobscheduler.FFJobService
      Network type: NetworkRequest [ NONE id=0, [ Capabilities: INTERNET&TRUSTED&NOT_VPN ] ]
      Minimum latency: +3h0m0s0ms
    Required constraints: TIMING_DELAY CONNECTIVITY [0xd0200000]
    Network: 191
    Last successful run: 2027-11-12 08:00:00
  JOB androidx.work.systemjobscheduler:u0a426/289: 8896dcb #IdentityHashWorker#@androidx.work.systemjobscheduler@com.facebook.katana/androidx.work.impl.background.systemjob.SystemJobService
    u0a426 tag=*job*r/#IdentityHashWorker#@androidx.work.systemjobscheduler@com.facebook.katana/androidx.work.impl.background.systemjob.SystemJobService
    Trace tag: IdentityHashWorker
  JOB androidx.work.systemjobscheduler:u0a500/7: 1a2b3c4 #BankSyncWorker#@androidx.work.systemjobscheduler@com.example.bank/androidx.work.impl.background.systemjob.SystemJobService
    Source: uid=u0a500 user=0 pkg=com.example.bank
    Trace tag: BankSyncWorker
    Last successful run: 2027-11-12 07:00:00
ConnectivityController:
  Available networks:
    191: CNM{[ Transports: VPN Capabilities: INTERNET ] uid=10777}
  Subscription ID signal strengths:
    2: 1
CountQuotaTracker:
    <0>com.example.bank::timeout-reg:
      count: 3
    <0>com.facebook.katana::timeout-reg:
      count: 1
ComponentController:
  0-ComponentInfo{com.example.bank/androidx.work.impl.background.systemjob.SystemJobService}: com.example.bank
  0-ComponentInfo{com.facebook.katana/com.facebook.falco.jobscheduler.FFJobService}: com.facebook.katana
TimeController:
  ##u0a426/10001 from u0a426: Delay=-1m, Deadline=+2m
  #androidx.work.systemjobscheduler:u0a500/7 from u0a500: com.example.bank RUNNABLE
Cached UID->package map:
  10426: {com.facebook.katana}
  10500: {com.example.bank, com.example.bank.helper}
  1000: {android, com.example.bank}
Historical stats at 2027-11-12-08-45-00 (-30m) over +30m0s0ms:
  u0a500 / com.example.bank:
    Job 1 started
  u0a426 / com.facebook.katana:
    Job 2 started
Recently completed jobs:
  -1m14s674ms
      9b5df72 {androidx.work.systemjobscheduler} #u0a500/7 #BankSyncWorker#@androidx.work.systemjobscheduler@com.example.bank/androidx.work.impl.background.systemjob.SystemJobService
      Trace tag: BankSyncWorker
      Priority: 300 [DEFAULT]
  -2m0s0ms
      1c2d3e4 {androidx.work.systemjobscheduler} #u0a426/289 #IdentityHashWorker#@androidx.work.systemjobscheduler@com.facebook.katana/androidx.work.impl.background.systemjob.SystemJobService
      Trace tag: IdentityHashWorker
"""

ALARMS = """\
Current Alarm Manager state:
  nowRTC=1826028900000=2027-11-12 09:15:00.000 nowELAPSED=95405377
  Pending alarm batches: 2
    RTC #1: Alarm{156633 type 1 origWhen 1826007000000 whenElapsed 31631203677 com.example.bank}
      tag=*alarm*:org.example.vendor.intent.SYNC
      type=RTC origWhen=2027-11-12 09:10:00.000 window=+1h0m0s0ms repeatInterval=0 count=0 flags=0x0
      operation=PendingIntent{cb23df0: PendingIntentRecord{e63af69 com.example.bank broadcastIntent}}
    ELAPSED_WAKEUP #2: Alarm{ee17d68 type 2 origWhen 95000000 whenElapsed 95500000 com.facebook.katana}
      tag=*walarm*:WakingExecutorService.ACTION_ALARM.com.facebook.katana.Mqtt_Wakeup
      operation=PendingIntent{a84581: PendingIntentRecord{f991626 com.facebook.katana broadcastIntent}}
  Last alarm deliveries:
    com.example.bank, u0: -30m55s971ms, -47m52s589ms,
    com.facebook.katana, u0: -55m4s573ms,
  Top alarms:
  u0a500:com.example.bank +1s373ms running, 7 wakeups:
      *walarm*:org.example.vendor.intent.SYNC
  u0a426:com.facebook.katana +1s0ms running, 12 wakeups:
      *walarm*:WakingExecutorService.ACTION_ALARM.com.facebook.katana.Mqtt_Wakeup
"""


def capture() -> Redactor:
    r = Redactor()
    r.harvest(SYSTEM, "pm-list-packages-system.txt")
    r.harvest(THIRD_PARTY, "pm-list-packages-3p.txt")
    r.harvest(f"{CAPTURE_EPOCH}\n", "date-epoch.txt")
    r.harvest("[persist.sys.timezone]: [America/New_York]\n", "getprop.txt")
    return r


def test_jobscheduler_drops_other_apps_whole_and_keeps_facebook() -> None:
    r = capture()
    out = r.redact(JOBS, "dumpsys-jobscheduler.txt")
    for leak in ["com.example.bank", "BankSyncWorker", "org.example"]:
        assert leak not in out, leak
    assert "#IdentityHashWorker#@androidx.work.systemjobscheduler@com.facebook.katana/" in out
    assert out.count("Trace tag: IdentityHashWorker") == 2
    assert "<0>com.facebook.katana::timeout-reg:\n      count: 1" in out
    assert "      count: 3" not in out  # the bank's quota block went with its header
    assert "  10426: {com.facebook.katana}\n" in out
    assert "  1000: {android}\n" in out  # list filtered, not the line
    assert "10500:" not in out
    assert "  u0a426 / com.facebook.katana:\n    Job 2 started" in out
    assert "Job 1 started" not in out
    assert scan(out, r.packages, "dumpsys-jobscheduler.txt") == []


def test_network_details_are_dropped() -> None:
    out = capture().redact(JOBS, "dumpsys-jobscheduler.txt")
    for gone in [
        "NetworkRequest",
        "CNM{",
        "Transports",
        "Network: 191",
        "Subscription ID",
        "uid=10777",
    ]:
        assert gone not in out, gone
    assert "ConnectivityController:\nCountQuotaTracker:" in out  # header kept, body gone
    assert (
        "Required constraints: TIMING_DELAY CONNECTIVITY" in out
    )  # the job's own constraints stay
    assert "network_detail" in {f.category for f in scan(JOBS)}


def test_job_ids_get_capture_scoped_placeholders() -> None:
    r = capture()
    out = r.redact(JOBS, "dumpsys-jobscheduler.txt")
    assert "JOB #u0a426/1: 568bf2b" in out
    assert "##u0a426/1 from u0a426" in out  # the same job keeps the same placeholder
    assert "systemjobscheduler:u0a426/2: 8896dcb" in out
    assert "#u0a426/2 #IdentityHashWorker#" in out
    assert "10001" not in out and "/289" not in out
    # A second capture gets its own numbering: nothing links across captures.
    other = capture().redact(JOBS.replace("u0a426/10001", "u0a426/55"), "dumpsys-jobscheduler.txt")
    assert "JOB #u0a426/1: 568bf2b" in other


def test_dashed_stats_time_is_shifted() -> None:
    out = capture().redact(JOBS, "dumpsys-jobscheduler.txt")
    # 08:45 local (New York, UTC-5) is 13:45Z, 30 min before the 14:15Z capture.
    assert "Historical stats at 2029-12-31-23-30-00 (-30m)" in out
    assert "unshifted_time" in {f.category for f in scan(JOBS)}


def test_alarm_entries_and_stats_go_whole() -> None:
    r = capture()
    out = r.redact(ALARMS, "dumpsys-alarm.txt")
    for leak in ["com.example.bank", "org.example"]:
        assert leak not in out, leak
    assert "RTC #1:" not in out and "origWhen=" not in out  # the whole pending entry
    assert "WakingExecutorService.ACTION_ALARM.com.facebook.katana.Mqtt_Wakeup" in out
    assert "u0a426:com.facebook.katana +1s0ms running, 12 wakeups:" in out
    assert "    com.facebook.katana, u0: -55m4s573ms," in out
    assert "nowRTC=1893456000000=2030-01-01 00:00:00.000" in out  # epoch ms and local, shifted
    assert scan(out, r.packages, "dumpsys-alarm.txt") == []
    found = {f.value for f in scan(ALARMS, r.packages) if f.category == "package"}
    assert found == {"com.example.bank"}


def test_job_extras_are_emptied() -> None:
    text = (
        "    Extras: {accountName=alice@mailbox.test, accountType=com.google, user_id=8812}\n"
        "    Transient extras: {_background_task_extras=Bundle[{token=abc123}]}\n"
        "    Extras: {}\n"
    )
    out = capture().redact(text, "dumpsys-jobscheduler.txt")
    assert out == "    Extras: {REDACTED}\n    Transient extras: {REDACTED}\n    Extras: {}\n"
    assert scan(out) == []
    assert "job_extras" in {f.category for f in scan(text)}


UID_HISTORY = """\
Current Alarm Manager state:
  Cancelled alarms:
    u0a426:
      #1: Reason=alarm_cancelled elapsed=-54m55s676ms
        Snapshot:
          type=ELAPSED_WAKEUP tag=*walarm*:WakingExecutorService.ACTION_ALARM.com.facebook.katana.Mqtt_Wakeup
    u0a500:
      #1: Reason=alarm_cancelled elapsed=-20h53m29s683ms
        Snapshot:
          type=RTC tag=*alarm*:org.example.vendor.intent.TUNNEL_KEEPALIVE
    u0a777:
      #1: Reason=alarm_cancelled elapsed=-1h0m0s0ms
"""
PACKAGES = (
    "Packages:\n"
    "  Package [com.facebook.katana] (a1):\n    appId=10426\n"
    "  Package [com.example.bank] (b2):\n    appId=10500\n"
)


def test_uid_owned_blocks_need_an_allowed_owner() -> None:
    """A bare `u0aN:` block is kept only if the capture shows its packages are allowed.
    The bank's block goes whole, although its tag doesn't name the package, and so
    does a UID the capture says nothing about."""
    r = capture()
    r.harvest(PACKAGES, "dumpsys-package-packages.txt")
    out = r.redact(UID_HISTORY, "dumpsys-alarm.txt")
    assert "u0a426:" in out and "katana.Mqtt_Wakeup" in out
    assert "u0a500" not in out and "TUNNEL_KEEPALIVE" not in out and "-20h53m" not in out
    assert "u0a777" not in out
    assert scan(out, r.packages) == []
    assert {f.value for f in scan(UID_HISTORY, r.packages) if f.category == "package"} == {
        "u0a500",
        "u0a777",
    }


def test_totals_are_recounted_after_trimming() -> None:
    jobs = (
        "Registered 758 jobs:\n"
        "  JOB #1000/1: a1 android/com.android.server.X\n    Source: uid=1000 user=0 pkg=android\n"
        "  JOB #1000/2: b2 android/com.android.server.Y\n"
        "PrefetchController:\n"
    )
    alarms = (
        "Current Alarm Manager state:\n"
        "  148 pending alarms: \n"
        "    RTC #1: Alarm{a1 type 1 origWhen 0 whenElapsed 1 android}\n      tag=*alarm*:x\n"
        "    ELAPSED #2: Alarm{b2 type 3 origWhen 0 whenElapsed 2 android}\n"
        "  Pending alarms per uid: [1000:3, u0a426:2]\n"
    )
    r = capture()
    assert "Registered 2 jobs:" in r.redact(jobs, "dumpsys-jobscheduler.txt")
    out = r.redact(alarms, "dumpsys-alarm.txt")
    assert "  2 pending alarms: \n" in out
    assert "Pending alarms per uid: [1000:3, u0a426:2]" in out  # an independent statistic
    # Untrimmed (consistent) totals are left alone.
    ok = jobs.replace("Registered 758 jobs:", "Registered 2 jobs:")
    assert capture().redact(ok, "dumpsys-jobscheduler.txt").startswith("Registered 2 jobs:")


def test_alarm_stats_wakeups_are_resummed_after_trimming() -> None:
    """On full dumps an app's header wakeups equal the sum of its tags' wakes, so the
    header describes what is listed and is recomputed when tags are trimmed."""
    stats = (
        "Current Alarm Manager state:\n"
        "  Alarm Stats:\n"
        "  1000:android +1s0ms running, 298 wakeups:\n"
        "    +1s0ms 100 wakes 120 alarms, last -1s0ms:\n"
        "      *walarm*:x\n"
        "    +1s0ms 10 wakes 10 alarms, last -1s0ms:\n"
        "      *walarm*:y\n"
        "    0 1 wakes 1 alarms, last -1s0ms:\n"
        "      *walarm*:w\n"
        "  u0a426:com.facebook.katana +5s256ms running, 24 wakeups:\n"
        "    +5s256ms 24 wakes 24 alarms, last -30m55s971ms:\n"
        "      *walarm*:z\n"
    )
    out = capture().redact(stats, "dumpsys-alarm.txt")
    assert "  1000:android +1s0ms running, 111 wakeups:\n" in out
    assert "  u0a426:com.facebook.katana +5s256ms running, 24 wakeups:\n" in out


def test_job_network_type_keeps_only_unmetered_or_any() -> None:
    text = (
        "  JOB #u0a426/1: a1 com.facebook.katana/com.facebook.A\n"
        "      Network type: NetworkRequest [ NONE id=0, [ Capabilities: INTERNET&NOT_METERED&NOT_VPN ] ]\n"
        "  JOB #u0a426/2: b2 com.facebook.katana/com.facebook.B\n"
        "      Network type: NetworkRequest [ NONE id=0, [ Capabilities: INTERNET&TRUSTED&VALIDATED ] ]\n"
    )
    out = capture().redact(text, "dumpsys-jobscheduler.txt")
    assert "Network type: unmetered\n" in out and "Network type: any\n" in out
    assert "NetworkRequest" not in out and "NOT_VPN" not in out
    assert scan(out) == []
