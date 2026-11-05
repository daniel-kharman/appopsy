"""redact-fixture on the launcher query: every app with an icon is listed, so
non-allowed third-party apps go whole, the rest are renumbered and recounted."""

from __future__ import annotations

from datetime import UTC, datetime

from appopsy.redact import Redactor, scan
from appopsy.redact_packages import PackagePolicy

SYSTEM = "package:android\npackage:com.google.android.apps.maps\n"
THIRD_PARTY = (
    "package:com.facebook.katana  installer=com.android.vending\n"
    "package:com.example.bank  installer=com.android.vending\n"
)
LAUNCHER = """\
4 activities found:
  Activity #0:
    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true
    com.example.bank/.ui.MainActivity
  Activity #1:
    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
    com.facebook.katana/.LoginActivity
  Activity #2:
    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true
    org.example.vendor/com.example.vendor.Launcher
  Activity #3:
    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true
    com.google.android.apps.maps/com.google.android.maps.MapsActivity
"""


def capture() -> Redactor:
    r = Redactor()
    r.harvest(SYSTEM, "pm-list-packages-system.txt")
    r.harvest(THIRD_PARTY, "pm-list-packages-3p.txt")
    epoch = int(datetime(2027, 11, 12, 14, 15, tzinfo=UTC).timestamp())
    r.harvest(f"{epoch}\n", "date-epoch.txt")
    r.harvest("[persist.sys.timezone]: [America/New_York]\n", "getprop.txt")
    return r


def test_other_apps_go_whole_and_the_rest_is_renumbered() -> None:
    out = capture().redact(LAUNCHER, "pm-query-launcher.txt")
    for leak in ("com.example.bank", "org.example.vendor", "MainActivity", "Launcher"):
        assert leak not in out, leak
    assert out == (
        "2 activities found:\n"
        "  Activity #0:\n"
        "    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false\n"
        "    com.facebook.katana/.LoginActivity\n"
        "  Activity #1:\n"
        "    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true\n"
        "    com.google.android.apps.maps/com.google.android.maps.MapsActivity\n"
    )
    assert scan(out) == []


def test_scanner_flags_a_launcher_entry_left_in() -> None:
    policy = PackagePolicy()
    policy.harvest("pm-list-packages-system.txt", SYSTEM)
    found = policy.scan(LAUNCHER)
    assert {pkg for _, pkg in found} == {"com.example.bank", "org.example.vendor"}
