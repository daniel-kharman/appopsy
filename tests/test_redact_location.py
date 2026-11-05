"""Redaction of `dumpsys location` (synthetic data; coordinates are made up)."""

from __future__ import annotations

from datetime import UTC, datetime

from appopsy.redact import Redactor, scan

SYSTEM = "package:android\npackage:com.google.android.gms\npackage:com.google.android.dialer\n"
THIRD_PARTY = (
    "package:com.facebook.katana  installer=com.android.vending\n"
    "package:com.example.bank  installer=com.android.vending\n"
)
CAPTURE_EPOCH = int(datetime(2027, 11, 12, 14, 15, tzinfo=UTC).timestamp())

LOCATION = """\
Location Manager State:
  Location Settings:
    Location Setting: true
    Location Allow/Deny Packages:
      com.example.bank
    Emergency Bypass Allow Packages:
      com.google.android.dialer[*]
      com.google.android.gms[.thunderbird]
      com.example.bank[satellite_esos]
  Location Providers:
    fused provider:
      last location=Location[fused 12.345678,-45.678901 hAcc=13.0 et=+1d2h alt=812.4 vel=1.2 bear=90.0 {Bundle[{satellites=9}]}]
      listeners:
        10309/com.google.android.gms[fused_location_provider]/ab12 Request[@+5s, last location=Location[gps 12.345678,-45.678901 hAcc=4.0]}]
  Historical Aggregate Location Provider Data:
    fused:
      10426/com.facebook.katana: min/max interval = 5s/5s, total/active/foreground duration = +3s/+3s/+3s, locations = 2
      10500/com.example.bank: min/max interval = 60s/60s, total/active/foreground duration = +1h/+1h/0, locations = 40
  GNSS Manager:
    Position accuracy mean (m): 15.9876543210
    TTFF mean (sec): 5.1234567890
  Geofence Manager:
    service: registered
    Geofence[10500/com.example.bank 12.3456 -45.6789 r=150m]
      expires never
  Event Log:
    11-12 09:14:58.123: gps provider request = ProviderRequest[@1s, HIGH_ACCURACY, WorkSource{10309 com.google.android.gms, 10500 com.example.bank}]
    11-12 09:14:59.456: passive provider delivered location[1] to 10500/com.example.bank[tag]/9a8b
    11-12 09:15:00.000: passive provider delivered location[1] to 10426/com.facebook.katana/7c6d
"""


def capture() -> Redactor:
    r = Redactor()
    r.harvest(SYSTEM, "pm-list-packages-system.txt")
    r.harvest(THIRD_PARTY, "pm-list-packages-3p.txt")
    r.harvest(f"{CAPTURE_EPOCH}\n", "date-epoch.txt")
    r.harvest("[persist.sys.timezone]: [America/New_York]\n", "getprop.txt")
    return r


def test_location_records_are_replaced_whole() -> None:
    out = capture().redact(LOCATION, "dumpsys-location.txt")
    assert "last location=Location[fused REDACTED]\n" in out  # nested Bundle[...] included
    assert "last location=Location[gps REDACTED]}]" in out  # record inside a listener
    for gone in ["12.345678", "45.678901", "alt=", "vel=", "bear=", "satellites"]:
        assert gone not in out, gone
    assert "location_record" in {f.category for f in scan(LOCATION)}


def test_geofence_entries_go_whole() -> None:
    out = capture().redact(LOCATION, "dumpsys-location.txt")
    assert "  Geofence Manager:\n    service: registered\n  Event Log:" in out
    assert "Geofence[" not in out and "expires never" not in out
    assert "geofence" in {f.category for f in scan(LOCATION)}


def test_coordinate_pairs_are_flagged_anywhere() -> None:
    for text in [
        "  centre 12.3456789 -45.6789012 radius 10\n",
        "  point=12.34567;-45.67890\n",
        "  pos 12.34567/45.67890\n",
        "  lat=12.34, lon=-45.67\n",
        "  latitude: 12.3456 longitude: -45.6789\n",
    ]:
        assert {f.category for f in scan(text)} & {"coords", "coords_label"}, text
        assert scan(Redactor().redact(text)) == [], text
    # Single measurements with many decimals are not coordinates.
    assert (
        scan("    Position accuracy mean (m): 12.3456789012\n    TTFF mean (sec): 5.123456789\n")
        == []
    )


def test_event_log_times_shift_and_other_apps_go() -> None:
    r = capture()
    out = r.redact(LOCATION, "dumpsys-location.txt")
    # 09:15:00.000 local (New York, UTC-5) is the 14:15Z capture -> the anchor.
    assert "    12-31 23:59:58.123: gps provider request" in out
    assert (
        "    01-01 00:00:00.000: passive provider delivered location[1] to 10426/com.facebook.katana/"
        in out
    )
    assert "WorkSource{10309 com.google.android.gms}" in out  # list filtered, line kept
    assert "com.example.bank" not in out
    assert "10426/com.facebook.katana: min/max interval" in out
    assert "      com.google.android.dialer[*]" in out
    assert "      com.google.android.gms[.thunderbird]" in out
    assert scan(out, r.packages, "dumpsys-location.txt") == []
    # Year-less times are checked against a ~2-month window (the documented blind
    # spot covers Nov/Dec), so check the dotted format with a June time.
    assert [f.category for f in scan("    06-15 10:00:00.000: gps provider request\n")] == [
        "unshifted_time"
    ]


def test_bare_dotted_lines_outside_location_settings_are_not_packages() -> None:
    r = capture()
    text = "Domain verification status:\n  com.facebook.katana:\n    Domain verification state:\n      www.facebook.com: verified\n      m.facebook.com\n"
    assert r.redact(text) == text
