from __future__ import annotations

from pathlib import Path

from appopsy.parsers.launcher import parse_launcher

FIXTURE = Path(__file__).parent / "fixtures" / "17-google" / "capture-5" / "pm-query-launcher.txt"


def test_launcher_activities() -> None:
    activities, warnings = parse_launcher(FIXTURE.read_text())
    assert warnings == []
    assert len(activities) == 35  # matches the (recounted) "35 activities found:"
    packages = {a.package for a in activities}
    assert {"com.google.android.apps.maps", "com.google.android.dialer"} <= packages
    assert {"com.facebook.katana", "com.whatsapp", "com.twitter.android"} <= packages
    # Platform components have no launcher icon.
    assert not packages & {"android", "com.google.android.gms", "com.google.android.as"}
    maps = next(a for a in activities if a.package == "com.google.android.apps.maps")
    assert maps.activity == "com.google.android.maps.MapsActivity"
    assert FIXTURE.read_text().splitlines()[maps.line - 1].strip().startswith(maps.package + "/")


def test_unknown_lines_and_counts_become_warnings() -> None:
    text = (
        "2 activities found:\n"
        "  Activity #0:\n"
        "    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true\n"
        "    com.example.app/.Main\n"
        "  Something new\n"
    )
    activities, warnings = parse_launcher(text)
    assert [(a.package, a.activity) for a in activities] == [("com.example.app", ".Main")]
    assert sorted(w.message for w in warnings) == [
        "header says 2 activities, found 1",
        "unrecognised launcher line",
    ]
    assert parse_launcher("")[1] == []  # e.g. a fake device in tests: nothing to say
