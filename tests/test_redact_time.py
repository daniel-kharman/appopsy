"""Shifting every timestamp in a capture so the capture happens at the anchor."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from appopsy.redact import Redactor, redact_tree, scan
from appopsy.redact_time import ANCHOR, ANCHOR_EPOCH, CaptureClock, TimeShiftError

# A made-up capture at 2027-11-12 09:15:00 America/New_York (UTC-5, after the
# 7 November 2027 DST change), i.e. 14:15:00Z. No real capture times in tests.
CAPTURE_EPOCH = int(datetime(2027, 11, 12, 14, 15, tzinfo=UTC).timestamp())
OFFSET = ANCHOR_EPOCH - CAPTURE_EPOCH


def before_anchor(fmt: str, **delta: float) -> str:
    """The anchor minus ``delta``, formatted (tests don't hard-code the anchor)."""
    return (ANCHOR - timedelta(**delta)).strftime(fmt)


GETPROP = (
    "[persist.sys.timezone]: [America/New_York]\n"
    "[persist.sys.boot.reason.history]: [kernel_panic,tbugty_crashed,1825826400\n"
    "reboot,userrequested,1825048800]\n"
    "[ro.build.date.utc]: [1788490894]\n"
    "[ro.runtime.firstboot]: [1825048810123]\n"
)
APPOPS = (
    "    Package com.facebook.katana:\n"
    "      FINE_LOCATION (allow):\n"
    "        null=[\n"
    "          Access: [top-s] 2027-11-12 09:15:00.250 (-638ms)\n"
    "          Reject: [bg-s]2027-11-12 08:52:30.400 (-21m14s536ms)\n"
    "          Reject: [fg-s]2027-10-20 14:05:10.120 (-16d16h14m32s967ms)\n"
    "        ]\n"
    "10426|com.facebook.katana|default:0|FINE_LOCATION|null|2027-11-12 09:15:00.250|1|0|0|top|s|-1|0\n"
    "    timeStamp=2027-11-01 12:00:00\n"
)


def capture() -> Redactor:
    r = Redactor()
    r.harvest(f"{CAPTURE_EPOCH}\n", "date-epoch.txt")
    r.harvest("2027-11-12T09:15:00-0500\n", "date-local.txt")
    r.harvest(GETPROP, "getprop.txt")
    return r


def test_date_files_land_on_the_anchor() -> None:
    r = capture()
    assert r.redact(f"{CAPTURE_EPOCH}\n", "date-epoch.txt") == f"{ANCHOR_EPOCH}\n"
    assert r.redact("2027-11-12T09:15:00-0500\n", "date-local.txt") == (
        ANCHOR.strftime("%Y-%m-%dT%H:%M:%S+0000") + "\n"
    )


def test_local_times_shift_by_one_offset_in_utc_and_keep_their_spacing() -> None:
    out = capture().redact(APPOPS, "dumpsys-appops.txt")
    # 09:15:00.250 local (UTC-5) is the capture moment +0.25 s -> anchor +0.25 s.
    stamp = (ANCHOR + timedelta(milliseconds=250)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    assert f"Access: [top-s] {stamp} (-638ms)" in out
    # 22m29.6s earlier, still 22m29.6s earlier.
    earlier = before_anchor("%Y-%m-%d %H:%M:%S.%f", minutes=22, seconds=29.6)[:-3]
    assert f"Reject: [bg-s]{earlier} (-21m14s536ms)" in out
    # 20 October was summer time (UTC-4): the timezone, not the capture's -0500, decides.
    expected = datetime(2027, 10, 20, 18, 5, 10, 120000, tzinfo=UTC).timestamp() + OFFSET
    assert f"[fg-s]{datetime.fromtimestamp(expected, UTC):%Y-%m-%d %H:%M:%S.%f}"[:-3] in out
    assert f"|{stamp}|" in out  # the 1-hour table too
    assert "timeStamp=2000-01-01 00:00:00" in out  # install times are normalised, not shifted


def test_getprop_boot_times_shift_but_build_dates_dont() -> None:
    out = capture().redact(GETPROP, "getprop.txt")
    assert f"tbugty_crashed,{1825826400 + OFFSET}\n" in out
    assert f"userrequested,{1825048800 + OFFSET}]" in out
    assert f"[ro.runtime.firstboot]: [{1825048810123 + OFFSET * 1000}]" in out
    assert "[ro.build.date.utc]: [1788490894]" in out


def test_shifted_capture_scans_clean_and_unshifted_one_does_not() -> None:
    r = capture()
    assert scan(r.redact(APPOPS, "x.txt"), name="x.txt") == []
    assert {f.category for f in scan(APPOPS)} >= {"unshifted_time"}
    assert [f.category for f in scan(f"{CAPTURE_EPOCH}\n", name="date-epoch.txt")] == [
        "unshifted_time"
    ]


def test_shift_is_idempotent() -> None:
    once = capture().redact(APPOPS, "dumpsys-appops.txt")
    again = Redactor()
    again.harvest(f"{ANCHOR_EPOCH}\n", "date-epoch.txt")
    again.harvest("[persist.sys.timezone]: [Etc/UTC]\n", "getprop.txt")
    assert again.redact(once, "dumpsys-appops.txt") == once


def test_timestamps_without_a_capture_clock_are_refused() -> None:
    with pytest.raises(TimeShiftError, match=r"no date-epoch\.txt"):
        Redactor().redact(APPOPS, "dumpsys-appops.txt")


def test_two_captures_in_one_run_are_refused(tmp_path: Path) -> None:
    for i, epoch in enumerate([CAPTURE_EPOCH, CAPTURE_EPOCH + 3600]):
        d = tmp_path / "raw" / f"capture-{i}"
        d.mkdir(parents=True)
        (d / "date-epoch.txt").write_text(f"{epoch}\n")
    with pytest.raises(TimeShiftError, match="more than one capture"):
        redact_tree([tmp_path / "raw"], tmp_path / "out", Redactor())


def test_offset_falls_back_to_the_date_offset_without_a_timezone() -> None:
    clock = CaptureClock()
    clock.harvest("date-local.txt", "2027-11-12T09:15:00-0500\n")
    assert clock.local_to_utc(datetime(2027, 10, 20, 14, 5, 10)) == datetime(
        2027, 10, 20, 19, 5, 10, tzinfo=UTC
    )


RESTRICTIONS = (
    "Historical restrictions\n"
    "    11-11 23:10:00:250 op: PLAY_AUDIO, usage: USAGE_NOTIFICATION: Restriction[mode: ignore,"
    " exceptions: [com.google.android.dialer, com.example.bank, com.whatsapp]]\n"
    "    11-12 06:40:00:125 op: PLAY_AUDIO, usage: USAGE_NOTIFICATION: restriction removed\n"
)


def test_year_less_restriction_times_shift_and_exceptions_are_filtered() -> None:
    r = capture()
    r.harvest("package:com.google.android.dialer\n", "pm-list-packages-system.txt")
    out = r.redact(RESTRICTIONS, "dumpsys-appops.txt")
    # 23:10 local on 11 Nov (UTC-5) is 04:10Z on 12 Nov, 10h05m before the capture -> anchor - 10h05m.
    first = before_anchor("%m-%d %H:%M:%S", hours=10, minutes=4, seconds=59.75)
    second = before_anchor("%m-%d %H:%M:%S", hours=2, minutes=34, seconds=59.875)
    assert f"    {first}:250 op: PLAY_AUDIO" in out
    assert f"    {second}:125 op: PLAY_AUDIO" in out
    assert "exceptions: [com.google.android.dialer, com.whatsapp]" in out
    assert scan(out, r.packages, "dumpsys-appops.txt") == []
    # Year-less times are only checked against a ~2-month window before the anchor:
    # a June time is caught, but a real November time can't be told from a shifted
    # one. That's a known blind spot; redaction, not the scan, is what shifts them.
    assert [f.category for f in scan("    06-15 23:10:00:250 op: X\n")] == ["unshifted_time"]
    assert scan(RESTRICTIONS.replace(", com.example.bank", "")) == []


def test_scan_window_catches_real_times_before_the_anchor_too() -> None:
    """With the anchor in 2030, a real 2026 time is *before* it; it must still be flagged."""
    real = "Reject: [bg-s]2027-11-12 08:52:30.400 (-21m14s536ms)\n"
    assert [f.category for f in scan(real)] == ["unshifted_time"]
    shifted = f"Reject: [bg-s]{before_anchor('%Y-%m-%d %H:%M:%S', minutes=21)}.600 (-21m)\n"
    assert scan(shifted) == []
    assert [f.category for f in scan("1826007300\n", name="date-epoch.txt")] == ["unshifted_time"]


def test_scan_window_allows_scheduled_future_times_and_sentinels() -> None:
    """Alarms and job deadlines are scheduled ahead: a shifted alarm 149 days after
    the capture is fine, and so is a ~100-year "never" placeholder."""
    ahead = (ANCHOR + timedelta(days=149)).strftime("%Y-%m-%d %H:%M:%S")
    sentinel = (ANCHOR + timedelta(days=36523)).strftime("%Y-%m-%d %H:%M:%S")
    assert scan(f"    type=RTC origWhen={ahead}.000 window=0\n") == []
    assert scan(f"    type=RTC_WAKEUP origWhen={sentinel}.000 window=0\n") == []
    too_far = (ANCHOR + timedelta(days=500)).strftime("%Y-%m-%d %H:%M:%S")
    assert [f.category for f in scan(f"    origWhen={too_far}.000\n")] == ["unshifted_time"]
