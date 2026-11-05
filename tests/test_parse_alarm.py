from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from appopsy.parsers.alarm import AlarmSnapshot, parse_alarms

FIXTURE = Path(__file__).parent / "fixtures" / "17-google" / "capture-2" / "dumpsys-alarm.txt"


@pytest.fixture(scope="module")
def snap() -> AlarmSnapshot:
    snapshot, warnings = parse_alarms(FIXTURE.read_text())
    assert warnings == []
    return snapshot


def test_clock_and_window(snap: AlarmSnapshot) -> None:
    assert snap.now == datetime(2030, 1, 1, 0, 0, 0, 249000)
    assert snap.runtime_elapsed == timedelta(
        days=1, hours=2, minutes=29, seconds=47, milliseconds=850
    )


def test_pending_alarms(snap: AlarmSnapshot) -> None:
    assert len(snap.pending) == 65  # matches the (recounted) "65 pending alarms:"
    assert sum(a.wakeup for a in snap.pending) == 23  # ELAPSED_WAKEUP + RTC_WAKEUP
    fb = [a for a in snap.pending if a.package == "com.facebook.katana"]
    assert len(fb) == 1
    alarm = fb[0]
    assert (alarm.type, alarm.wakeup) == ("RTC", False)
    assert alarm.orig_when == datetime(2030, 1, 1, 20, 43, 30, 343000)
    assert alarm.window == timedelta(hours=1)
    assert (alarm.repeat_interval, alarm.count) == (timedelta(0), 0)
    elapsed = next(a for a in snap.pending if a.type == "ELAPSED")
    assert elapsed.orig_when is None and elapsed.orig_when_in is not None


def test_wakeup_stats_and_mqtt(snap: AlarmSnapshot) -> None:
    fb = snap.stats_for("com.facebook.katana")
    assert fb is not None
    assert (fb.label, fb.uid, fb.wakeups) == ("u0a426", 10426, 24)
    assert fb.running == timedelta(seconds=5, milliseconds=256)
    (tag,) = fb.tags
    assert tag.tag == "*walarm*:WakingExecutorService.ACTION_ALARM.com.facebook.katana.Mqtt_Wakeup"
    assert (tag.wakeups, tag.alarms) == (24, 24)
    assert tag.last_ago == timedelta(minutes=30, seconds=55, milliseconds=971)
    # What `chatty-wakeups` compares with a threshold: wakeups per hour since boot.
    rate = snap.wakeups_per_hour("com.facebook.katana")
    assert rate is not None and 0.9 < rate < 0.95
    system = snap.stats_for("android")
    assert system is not None and system.uid == 1000
    assert snap.wakeups_per_hour("com.example.absent") is None


def test_zero_running_time_is_printed_as_0() -> None:
    text = (
        "  Alarm Stats:\n"
        "  1000:android 0 running, 3 wakeups:\n"
        "    0 1 wakes 1 alarms, last -1h32m20s534ms:\n"
        "      *walarm*:a\n"
        "    +1s0ms 2 wakes 2 alarms, last -1s0ms:\n"
        "      *walarm*:b\n"
    )
    snap, warnings = parse_alarms(text)
    assert warnings == []
    (stats,) = snap.stats
    assert stats.running == timedelta(0)
    assert [(t.tag, t.wakeups, t.running) for t in stats.tags] == [
        ("*walarm*:a", 1, timedelta(0)),
        ("*walarm*:b", 2, timedelta(seconds=1)),
    ]


def test_unknown_lines_become_warnings() -> None:
    text = (
        "Current Alarm Manager state:\n"
        "  2 pending alarms: \n"
        "    RTC #1: Alarm{a1 type 1 origWhen 0 whenElapsed 1 android}\n"
        "      type=RTC origWhen=sometime window=0 repeatInterval=0 count=0 flags=0x0\n"
        "  Alarm Stats:\n"
        "  1000:android +1s0ms running, many wakeups:\n"
    )
    snap, warnings = parse_alarms(text)
    assert len(snap.pending) == 1 and snap.pending[0].orig_when is None
    assert sorted(w.message for w in warnings) == [
        "unrecognised alarm line",
        "unrecognised stats line",
    ]
