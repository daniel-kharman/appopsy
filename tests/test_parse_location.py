from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from appopsy.parsers.location import LocationSnapshot, parse_location

FIXTURE = Path(__file__).parent / "fixtures" / "17-google" / "capture-3" / "dumpsys-location.txt"


@pytest.fixture(scope="module")
def snap() -> LocationSnapshot:
    snapshot, warnings = parse_location(FIXTURE.read_text())
    assert warnings == []
    return snapshot


def test_settings_and_providers(snap: LocationSnapshot) -> None:
    assert snap.enabled is True
    assert [p.name for p in snap.providers] == ["passive", "network", "fused", "gps"]
    passive = snap.providers[0]
    assert passive.enabled is True and passive.allowed is True
    assert passive.last_location_redacted  # the record is in the file, but redacted
    hidden = [lst for lst in passive.listeners if lst.hidden_from_appops]
    assert hidden and all(lst.package == "com.google.android.gms" for lst in hidden)


def test_aggregates(snap: LocationSnapshot) -> None:
    assert len(snap.aggregates) == 22
    fb = snap.aggregates_for("com.facebook.katana")
    assert sorted((a.provider, a.locations) for a in fb) == [
        ("gps", 0),
        ("network", 1),
        ("passive", 3),
    ]
    gps = next(a for a in fb if a.provider == "gps")
    assert (gps.uid, gps.min_interval, gps.max_interval) == (10426, "5s", "5s")
    assert gps.total == timedelta(seconds=2, milliseconds=241)
    assert gps.foreground == timedelta(seconds=2, milliseconds=240)
    assert gps.background == gps.total - gps.foreground


def test_system_app_long_requests_under_two_uids(snap: LocationSnapshot) -> None:
    """com.google.android.as: 6-hour interval requests active 11-15 h, under its own
    UID and its secondary UID. Facts for the rules; framing is the rules' job."""
    asi = {
        a.uid: a for a in snap.aggregates_for("com.google.android.as") if a.provider == "network"
    }
    assert set(asi) == {10168, 30168}
    assert asi[10168].min_interval == "21600s"
    assert asi[10168].total == timedelta(hours=11, minutes=31, seconds=30, milliseconds=424)
    assert asi[30168].total == timedelta(hours=15, minutes=26, seconds=22, milliseconds=194)


def test_event_log(snap: LocationSnapshot) -> None:
    kinds = {(e.provider, e.kind) for e in snap.events}
    assert ("passive", "delivered") in kinds and ("gps", "request") in kinds
    assert ("gnss_measurements", "+registration") in kinds
    delivered = [e for e in snap.events if e.kind == "delivered"]
    assert len(delivered) == 158
    assert all(e.count is not None and e.package for e in delivered)
    first = snap.events[0]
    assert (
        first.stamp == "12-31 23:00:29.059"
        and first.provider == "network"
        and first.kind == "request"
    )


def test_unknown_lines_become_warnings() -> None:
    text = (
        "Location Manager State:\n"
        "  Historical Aggregate Location Provider Data:\n"
        "    gps:\n"
        "      10426/com.facebook.katana: something new\n"
        "  Event Log:\n"
        "    12-31 23:00:29.059: gps provider teleported\n"
    )
    snap, warnings = parse_location(text)
    assert snap.aggregates == []
    assert [e.kind for e in snap.events] == ["other"]
    assert [w.message for w in warnings] == ["unrecognised aggregate line"]
