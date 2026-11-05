from __future__ import annotations

from datetime import date
from pathlib import Path

from appopsy.parsers.getprop import device_info, parse_getprop
from appopsy.redact_time import ANCHOR_EPOCH

FIXTURE = Path(__file__).parent / "fixtures" / "17-google" / "capture-1" / "getprop.txt"


def test_parse_real_getprop() -> None:
    props, warnings = parse_getprop(FIXTURE.read_text())
    assert warnings == []
    assert len(props) > 1000
    assert props["ro.product.model"] == "Pixel 11 Pro"
    assert props["ro.serialno"] == "FAKESERIAL0001"
    assert props["net.bt.name"] == "Android"
    assert props["debug.atrace.app_number"] == ""


def test_multiline_value_is_joined() -> None:
    props, _ = parse_getprop(FIXTURE.read_text())
    history = props["persist.sys.boot.reason.history"]
    # Boot times are shifted with the rest of the capture: 1d1h21m25s and
    # 9d23h34m14s before the capture, which sits on the anchor.
    assert history.splitlines() == [
        f"kernel_panic,tbugty_crashed,{ANCHOR_EPOCH - 91285}",
        f"reboot,userrequested,{ANCHOR_EPOCH - 862454}",
    ]


def test_device_info_from_real_getprop() -> None:
    props, _ = parse_getprop(FIXTURE.read_text())
    info = device_info(props)
    assert info.manufacturer == "Google"
    assert info.model == "Pixel 11 Pro"
    assert info.android_release == "17"
    assert info.sdk == 37
    assert info.security_patch == date(2026, 10, 5)
    assert info.build_fingerprint is not None
    assert info.build_fingerprint.startswith("google/grizzly/grizzly:17/")
    assert info.timezone is not None


def test_unparseable_lines_become_warnings() -> None:
    text = "[a.b]: [1]\ngarbage line\n[c.d]: [2]\n[e.f]: [never closed\n"
    props, warnings = parse_getprop(text)
    assert props == {"a.b": "1", "c.d": "2"}
    assert [w.line for w in warnings] == [2, 4]


def test_device_info_tolerates_missing_and_bad_values() -> None:
    info = device_info({"ro.build.version.sdk": "x", "ro.build.version.security_patch": "soon"})
    assert info.sdk is None
    assert info.security_patch is None
    assert info.model is None
