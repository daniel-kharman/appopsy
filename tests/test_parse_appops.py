from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from appopsy.parsers.appops import (
    AppOpsSnapshot,
    OpCategory,
    UidRole,
    link_uids,
    op_category,
    parse_appops,
)
from appopsy.parsers.dumpsys_package import parse_dumpsys_package
from appopsy.redact_time import ANCHOR

CAPTURE = Path(__file__).parent / "fixtures" / "17-google" / "capture-1"


@pytest.fixture(scope="module")
def snap() -> AppOpsSnapshot:
    snapshot, warnings = parse_appops((CAPTURE / "dumpsys-appops.txt").read_text())
    assert warnings == []
    return snapshot


def test_uid_blocks(snap: AppOpsSnapshot) -> None:
    assert [u.label for u in snap.uids] == ["u0a168", "u0a179", "u0a231", "u0a426", "u0a20168"]
    fb = snap.uid(10426)
    assert fb is not None
    assert (fb.user_id, fb.app_id, fb.state) == (0, 10426, "cch")
    assert len(fb.modes) == 48
    assert [p.name for p in fb.packages] == ["com.facebook.katana"]
    assert len(fb.packages[0].ops) == 22
    # The same package can appear under two UIDs; the table calls the second one 30168.
    assert [u.uid for u in snap.for_package("com.google.android.as")] == [10168, 30168]


def test_two_layers_uid_mode_overrides_package_mode(snap: AppOpsSnapshot) -> None:
    """Facebook: package-level FINE_LOCATION is 'allow' but the UID mode is 'foreground'."""
    fb = snap.uid(10426)
    assert fb is not None
    fine = fb.packages[0].op("FINE_LOCATION")
    assert fine is not None
    assert fine.mode == "allow"
    assert fb.modes["FINE_LOCATION"] == "foreground"
    assert fb.effective_mode(fine) == "foreground"


def test_facebook_background_location_rejects(snap: AppOpsSnapshot) -> None:
    fine = snap.uid(10426).packages[0].op("FINE_LOCATION")  # type: ignore[union-attr]
    assert fine is not None
    assert [(e.kind, e.uid_state, e.attribution) for e in fine.events] == [
        ("access", "top", "s"),
        ("reject", "fg", "s"),
        ("reject", "bg", "s"),
        ("reject", "cch", "s"),
    ]
    bg = fine.events[2]
    # Shifted fixture time: 15m26.712s before the capture (the anchor), local = UTC.
    assert bg.time == ANCHOR.replace(tzinfo=None) - timedelta(
        minutes=15, seconds=26, milliseconds=712
    )
    assert bg.in_background and bg.attribution_tag is None and bg.proxy is None
    assert fine.events[0].duration is None


def test_monitor_location_is_a_request_not_a_delivery(snap: AppOpsSnapshot) -> None:
    """MONITOR_* records an active location request. Facebook has a MONITOR_LOCATION
    access in [bg-s] (duration +3ms), but every background FINE/COARSE event is a
    reject: no location was delivered in the background. Nothing may read the
    MONITOR_* access as 'location received in background'."""
    pkg = snap.uid(10426).packages[0]  # type: ignore[union-attr]
    monitor = pkg.op("MONITOR_LOCATION")
    assert monitor is not None
    assert monitor.category is OpCategory.LOCATION_REQUEST
    assert (monitor.switch_op, monitor.switch_mode) == ("COARSE_LOCATION", "allow")
    bg_request = [e for e in monitor.events if e.in_background]
    assert [(e.kind, e.uid_state, e.duration) for e in bg_request] == [
        ("access", "bg", timedelta(milliseconds=3))
    ]
    deliveries = pkg.events(OpCategory.LOCATION_DELIVERY)
    assert {op for op, _ in deliveries} == {"FINE_LOCATION", "COARSE_LOCATION"}
    assert [e for _, e in deliveries if e.in_background and e.kind == "access"] == []
    assert [e for _, e in deliveries if e.in_background and e.kind == "reject"]
    assert pkg.op("MONITOR_HIGH_POWER_LOCATION").category is OpCategory.LOCATION_REQUEST  # type: ignore[union-attr]


def test_op_categories() -> None:
    assert op_category("FINE_LOCATION") is OpCategory.LOCATION_DELIVERY
    assert op_category("COARSE_LOCATION") is OpCategory.LOCATION_DELIVERY
    assert op_category("MONITOR_LOCATION") is OpCategory.LOCATION_REQUEST
    assert op_category("MONITOR_HIGH_POWER_LOCATION") is OpCategory.LOCATION_REQUEST
    assert op_category("GPS") is OpCategory.LOCATION_HARDWARE
    assert op_category("CAMERA") is OpCategory.OTHER


def test_durations(snap: AppOpsSnapshot) -> None:
    gps = snap.uid(10426).packages[0].op("GPS")  # type: ignore[union-attr]
    assert gps is not None
    assert gps.events[0].duration == timedelta(seconds=2, milliseconds=890)


def test_proxy_chain(snap: AppOpsSnapshot) -> None:
    dialer = snap.uid(10179)
    assert dialer is not None
    accounts = dialer.packages[0].op("GET_ACCOUNTS")
    assert accounts is not None
    assert [(e.uid_state, e.attribution) for e in accounts.events] == [
        ("top", "tpd"), ("fgsvc", "tpd"), ("fg", "tpd"), ("bg", "tpd"), ("cch", "tpd"),
    ]  # fmt: skip
    proxy = accounts.events[0].proxy
    assert proxy is not None
    assert (proxy.uid, proxy.package) == (10309, "com.google.android.gms")
    assert proxy.attribution_tag


def test_recent_table(snap: AppOpsSnapshot) -> None:
    assert len(snap.recent) == 130
    fb_bg = [r for r in snap.recent if r.package == "com.facebook.katana" and r.uid_state == "bg"]
    assert len(fb_bg) == 8
    assert all(r.access_count == 0 and r.reject_count > 0 for r in fb_bg)
    assert {r.op for r in fb_bg} == {"FINE_LOCATION", "COARSE_LOCATION"}
    assert fb_bg[0].uid == 10426 and fb_bg[0].attribution_tag is None


def test_join_to_packages_by_uid(snap: AppOpsSnapshot) -> None:
    packages, _ = parse_dumpsys_package((CAPTURE / "dumpsys-package-packages.txt").read_text())
    by_name = {p.name: p for p in packages}
    for name in (
        "com.facebook.katana",
        "com.google.android.apps.maps",
        "com.google.android.dialer",
    ):
        assert by_name[name].app_id in {u.app_id for u in snap.for_package(name)}


SYNTHETIC = """\
AppOps Uid Op State
  Uid 1000:
    state=pers
      WAKE_LOCK: mode=allow
    Package android:
      WAKE_LOCK (allow):
        com.example.tag=[
          Access: [pers-s] 2025-12-31 10:00:00.000 (-14h) duration=+1h2m3s4ms
          Reject: [bg-up]2025-12-31 11:00:00.500 (-13h) proxy[uid=10500, pkg=com.example.notes, attributionTag=null]
          Running start at: +2m15s156ms
          startNesting=4
          this is not an event
        ]
  Uid u10a12:
    state=bg
  not a uid block
History:  mode=HISTORICAL_MODE_ENABLED_ACTIVE
UID|PACKAGE_NAME|DEVICE_ID|OP_NAME|ATTRIBUTION_TAG|ACCESS_TIME|ACCESS_COUNTS|REJECT_COUNTS|DURATION|UID_STATE|OP_FLAGS|ATTRIBUTION_CHAIN_ID|ATTRIBUTION_FLAGS
1000|android|default:0|WAKE_LOCK|com.example.tag|2025-12-31 10:00:00.000|1|0|3723004|pers|s|-1|0
broken|row
"""


def test_synthetic_shapes_and_warnings() -> None:
    snap, warnings = parse_appops(SYNTHETIC)
    system, work = snap.uids
    assert (system.uid, system.user_id, system.app_id) == (1000, 0, 1000)
    assert (work.label, work.user_id, work.app_id, work.uid) == ("u10a12", 10, 10012, 1010012)
    wake = system.packages[0].op("WAKE_LOCK")
    assert wake is not None
    access, reject = wake.events
    assert access.attribution_tag == "com.example.tag"
    assert access.duration == timedelta(hours=1, minutes=2, seconds=3, milliseconds=4)
    assert (reject.kind, reject.uid_state, reject.attribution) == ("reject", "bg", "up")
    assert reject.proxy is not None and reject.proxy.attribution_tag is None
    assert reject.time == datetime(2025, 12, 31, 11, 0, 0, 500000)
    assert wake.running_for == timedelta(minutes=2, seconds=15, milliseconds=156)
    assert wake.running_nesting == 4
    (row,) = snap.recent
    assert (row.uid, row.duration, row.attribution_tag) == (
        1000,
        timedelta(milliseconds=3723004),
        "com.example.tag",
    )
    assert sorted(w.text.strip() for w in warnings) == [
        "broken|row",
        "not a uid block",
        "this is not an event",
    ]


def test_no_uid_section() -> None:
    snap, warnings = parse_appops("AppOps Service state:\n")
    assert snap.uids == [] and snap.recent == []
    assert [w.message for w in warnings] == ["no AppOps Uid Op State section"]


def test_running_op_is_still_only_a_request(snap: AppOpsSnapshot) -> None:
    """`Running start at:` marks an op still in progress. Here com.google.android.as
    (second UID, 30168) has held a location *request* open for ~14 hours, which
    again says nothing about locations delivered."""
    asi = snap.uid(30168)
    assert asi is not None
    monitor = asi.packages[0].op("MONITOR_LOCATION")
    assert monitor is not None
    assert monitor.category is OpCategory.LOCATION_REQUEST
    assert monitor.running_for == timedelta(hours=13, minutes=49, seconds=29, milliseconds=269)
    start_fg = asi.packages[0].op("START_FOREGROUND")
    assert start_fg is not None and start_fg.running_for is not None
    fb_fine = snap.uid(10426).packages[0].op("FINE_LOCATION")  # type: ignore[union-attr]
    assert fb_fine is not None and fb_fine.running_for is None


def test_secondary_uid_is_linked_to_its_package_not_a_separate_app(snap: AppOpsSnapshot) -> None:
    """UID 30168 runs a com.google.android.as process but no package owns it
    (checked by hand on the device). It must come out as a secondary UID of
    com.google.android.as, decided by comparing with the package's own app id."""
    packages, _ = parse_dumpsys_package((CAPTURE / "dumpsys-package-packages.txt").read_text())
    links = {
        (link.uid, link.package): link
        for link in link_uids(snap, {p.name: p.app_id for p in packages})
    }
    primary = links[(10168, "com.google.android.as")]
    secondary = links[(30168, "com.google.android.as")]
    assert primary.role is UidRole.PRIMARY and primary.display_name == "com.google.android.as"
    assert secondary.role is UidRole.SECONDARY
    assert secondary.owner_uid == 10168
    assert secondary.display_name == "com.google.android.as (secondary UID 30168)"
    assert links[(10426, "com.facebook.katana")].role is UidRole.PRIMARY
    assert links[(10231, "com.google.android.apps.maps")].role is UidRole.PRIMARY  # shared UID


def test_uid_links_use_no_offset_rule() -> None:
    """Any UID other than the package's own is secondary, whatever the distance;
    without the package's app id the role is unknown, not guessed."""
    snap, _ = parse_appops(
        "AppOps Uid Op State\n"
        "  Uid u0a500:\n    Package com.example.notes:\n"
        "  Uid u0a2345:\n    Package com.example.notes:\n"
        "  Uid u10a20500:\n    Package com.example.notes:\n"
        "  Uid u0a77:\n    Package com.example.unknown:\n"
    )
    roles = {(link.uid, link.package): (link.role, link.owner_uid)
             for link in link_uids(snap, {"com.example.notes": 10500})}  # fmt: skip
    assert roles == {
        (10500, "com.example.notes"): (UidRole.PRIMARY, 10500),
        (12345, "com.example.notes"): (UidRole.SECONDARY, 10500),
        (1030500, "com.example.notes"): (UidRole.SECONDARY, 1010500),
        (10077, "com.example.unknown"): (UidRole.UNKNOWN, None),
    }
