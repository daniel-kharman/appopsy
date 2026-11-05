from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from appopsy.parsers.date import parse_device_clock
from appopsy.redact_time import ANCHOR

FIXTURES = Path(__file__).parent / "fixtures" / "17-google" / "capture-1"


def test_parse_real_device_clock() -> None:
    clock, warnings = parse_device_clock(
        (FIXTURES / "date-epoch.txt").read_text(), (FIXTURES / "date-local.txt").read_text()
    )
    assert warnings == []
    assert clock is not None
    # redact-fixture shifts every capture so it happens at the anchor, in UTC.
    assert clock.utc == ANCHOR
    assert clock.utc_offset == timedelta(0)
    assert clock.local is not None
    assert clock.local == ANCHOR


def test_parse_non_zero_offset() -> None:
    """Synthetic fixture: the anchor instant, seen from UTC+09:30."""
    synthetic = Path(__file__).parent / "fixtures" / "synthetic-0930"
    clock, warnings = parse_device_clock(
        (synthetic / "date-epoch.txt").read_text(), (synthetic / "date-local.txt").read_text()
    )
    assert warnings == []
    assert clock is not None
    assert clock.utc == ANCHOR
    assert clock.utc_offset == timedelta(hours=9, minutes=30)
    assert clock.local is not None
    assert clock.local == ANCHOR
    assert clock.local == clock.utc


def test_epoch_only() -> None:
    clock, warnings = parse_device_clock("1826007300\n", "")
    assert clock is not None
    assert clock.utc_offset is None
    assert clock.local is None
    assert [w.message for w in warnings] == ["no local time; UTC offset unknown"]


def test_epoch_and_local_disagree() -> None:
    clock, warnings = parse_device_clock("1826007300\n", "2027-11-12T09:15:00+0000\n")
    assert clock is not None
    assert "disagree" in warnings[0].message


def test_garbage_epoch() -> None:
    clock, warnings = parse_device_clock("date: bad format\n", "2027-11-12T09:15:00-0500\n")
    assert clock is None
    assert warnings
