"""Redactor and scanner behaviour on synthetic identifiers.

These values are made up (fictional number ranges, .test domains, documentation
IPs). Real-device data never goes in this file.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from appopsy import cli
from appopsy.redact import Redactor, is_placeholder, luhn_ok, redact_tree, scan

GETPROP = """\
[gsm.operator.alpha]: [Carrier One,Carrier Two]
[gsm.operator.iso-country]: [fr,fr]
[gsm.operator.numeric]: [20899,20898]
[gsm.sim.operator.alpha]: [Carrier One,Home Telco]
[gsm.sim.preiccid_0]: [8999123]
[net.bt.name]: [Android]
[persist.sys.device_name]: [Alices Phone]
[ro.boot.serialno]: [ZZ123ABC456]
[ro.boot.vbmeta.device]: [PARTUUID=11111111-2222-3333-4444-555555555555]
[ro.product.model]: [Pixel 11 Pro]
[ro.serialno]: [ZZ123ABC456]
"""

DUMPSYS = """\
  serial=ZZ123ABC456 device_name=Alices Phone
  Account {name=alice@mailbox.test, type=com.google}
  owner: bob.smith+work@corp.example.test
  imei=353456789012348 iccid=899912300000001232
  unlabelled imei 353456789012348 and a timestamp 172998765432109
  line1Number=+61491570156 tel:+61491570157
  wlan0 mac=a4:5e:60:12:34:56 bssid=A4-5E-60-12-34-57 zero=00:00:00:00:00:00
  ip=10.20.30.40 gw=192.168.1.1 loop=127.0.0.1 versionName=1.2.3.4
  ipv6=fe80::1c2d:3e4f:5a6b:7c8d full=2a00:1450:4007:080e:0000:0000:0000:200e
  SSID: "Home Network 5G" mSSID=CafeWifi
  Location[fused -33.856784,151.215297 hAcc=12.0]
  android_id=0123456789abcdef
"""


def test_luhn() -> None:
    assert luhn_ok("353456789012348")
    assert not luhn_ok("353456789012349")


def test_scan_finds_every_category() -> None:
    cats = {f.category for f in scan(GETPROP + DUMPSYS)}
    assert {
        "email", "account", "phone", "imei", "iccid", "mac", "ipv4", "ipv6", "ssid",
        "coords", "serial", "android_id", "carrier", "mccmnc", "country",
    } <= cats  # fmt: skip


def test_scan_ignores_non_identifiers() -> None:
    values = {f.value for f in scan(DUMPSYS)}
    assert "172998765432109" not in values  # 15 digits but not IMEI-shaped
    assert "00:00:00:00:00:00" not in values
    assert "127.0.0.1" not in values
    assert "1.2.3.4" not in values  # versionName


def test_redaction_leaves_nothing_and_is_consistent() -> None:
    r = Redactor()
    r.harvest(GETPROP)
    a, b = r.redact(GETPROP), r.redact(DUMPSYS)
    assert scan(a) == [] and scan(b) == []
    for secret in ["ZZ123ABC456", "alice@mailbox.test", "Alices Phone", "8999123",
                   "a4:5e:60:12:34:56", "Home Network 5G", "-33.856784", "+61491570156"]:  # fmt: skip
        assert secret not in a + b
    # Same serial -> same placeholder in both files and both getprop keys.
    assert a.count("FAKESERIAL0001") == 2
    assert "serial=FAKESERIAL0001" in b
    # Same carrier -> same placeholder in network and SIM fields.
    assert "[gsm.operator.alpha]: [carrier-1,carrier-2]" in a
    assert "[gsm.sim.operator.alpha]: [carrier-1,carrier-3]" in a
    # Shapes are preserved; generic and public values are untouched.
    assert "[net.bt.name]: [Android]" in a
    assert "[ro.product.model]: [Pixel 11 Pro]" in a
    assert "versionName=1.2.3.4" in b
    assert "loop=127.0.0.1" in b
    assert "Location[fused REDACTED]" in b  # the whole record, not just the pair


def test_redaction_is_idempotent() -> None:
    r = Redactor()
    r.harvest(GETPROP)
    once = r.redact(GETPROP + DUMPSYS)
    assert Redactor().redact(once) == once


def test_placeholders_are_recognised() -> None:
    r = Redactor()
    for category in ["email", "phone", "imei", "iccid", "mac", "ipv4", "ipv6", "serial"]:
        assert is_placeholder(category, r.placeholder(category, f"x-{category}"))


def test_extra_literals() -> None:
    r = Redactor(extra=["Alice Example"])
    assert r.redact("owner Alice Example here") == "owner REDACTED-ID-1 here"


def test_short_seed_only_matches_whole_tokens() -> None:
    r = Redactor()
    r.harvest("[gsm.sim.preiccid_0]: [8999123]\n")
    assert r.redact("ts=2089991239 id=8999123") == "ts=2089991239 id=REDACTED-ID-1"


def test_redact_tree_is_consistent_across_files(tmp_path: Path) -> None:
    src = tmp_path / "raw"
    (src / "sub").mkdir(parents=True)
    (src / "getprop.txt").write_text(GETPROP)
    (src / "sub" / "dumpsys.txt").write_text(DUMPSYS)
    (src / "blob.bin").write_bytes(b"\xff\xfe\x00")
    out = tmp_path / "out"
    result = redact_tree([src], out, Redactor())
    assert result.remaining == []
    assert [p.name for p, _ in result.skipped] == ["blob.bin"]
    assert "serial=FAKESERIAL0001" in (out / "sub" / "dumpsys.txt").read_text()


runner = CliRunner()


def test_cli_redact_and_check(tmp_path: Path) -> None:
    src = tmp_path / "raw"
    src.mkdir()
    (src / "getprop.txt").write_text(GETPROP)
    (src / "dumpsys.txt").write_text(DUMPSYS)
    out = tmp_path / "fixture"

    dirty = runner.invoke(cli.app, ["redact-fixture", "--check", str(src)])
    assert dirty.exit_code == 1
    assert "ZZ123ABC456" not in dirty.output  # values are masked in output

    done = runner.invoke(cli.app, ["redact-fixture", str(src), "--out", str(out)])
    assert done.exit_code == 0, done.output
    assert "Review the diff by hand" in " ".join(done.output.split())

    clean = runner.invoke(cli.app, ["redact-fixture", "--check", str(out)])
    assert clean.exit_code == 0, clean.output


@pytest.mark.parametrize(
    "args",
    [
        ["--out", "{src}/inside"],  # out inside source
        ["--out", "{nonempty}"],  # non-empty out without --force
        [],  # no --out
    ],
)
def test_cli_refuses_unsafe_outputs(tmp_path: Path, args: list[str]) -> None:
    src = tmp_path / "raw"
    src.mkdir()
    (src / "getprop.txt").write_text(GETPROP)
    nonempty = tmp_path / "nonempty"
    nonempty.mkdir()
    (nonempty / "x").write_text("x")
    argv = [a.format(src=src, nonempty=nonempty) for a in args]
    result = runner.invoke(cli.app, ["redact-fixture", str(src), *argv])
    assert result.exit_code == 2


NEUTRALISE = """\
[persist.sys.country]: [AU]
[persist.sys.language]: [en]
[persist.sys.locale]: [es-MX-u-mu-celsius]
[persist.sys.timezone]: [Australia/Adelaide]
[ro.product.locale]: [fr-FR]
[ro.product.locale.region]: [FR]
"""


def test_timezone_and_locale_are_neutralised() -> None:
    assert {f.category for f in scan(NEUTRALISE)} == {"timezone", "locale"}
    r = Redactor()
    out = r.redact(NEUTRALISE)
    assert out == (
        "[persist.sys.country]: [US]\n"
        "[persist.sys.language]: [en]\n"
        "[persist.sys.locale]: [en-US]\n"
        "[persist.sys.timezone]: [Etc/UTC]\n"
        "[ro.product.locale]: [en-US]\n"
        "[ro.product.locale.region]: [US]\n"
    )
    assert scan(out) == []
    assert r.mapping["timezone"] == {"Australia/Adelaide": "Etc/UTC"}


def test_per_device_and_per_install_values_are_normalised() -> None:
    text = (
        "[ro.boot.hw.soc.id]: [0123456789abcdef0123456789abcdef]\n"
        "[vendor.modem.soc_id]: [FEDCBA9876543210FEDCBA9876543210]\n"
        "[ro.boot.cdt_hwid]: [0x00000000000000000000000000000001]\n"
        "    User 0: ceDataInode=54321 deDataInode=12345 pccCeDataInode=0 installed=true\n"
        "        /data/resource-cache/com.android.systemui-accent-Ab3x.frro\n"
        "      Signing KeySets: 225\n"
        "  Package [com.whatsapp] (f39ba71):\n"  # per-boot object hash: kept
    )
    findings = {f.category for f in scan(text)}
    assert "device_id" in findings and "inode" in findings and "overlay_suffix" in findings
    r = Redactor()
    r.harvest(text)
    out = r.redact(text)
    assert scan(out) == []
    assert "0123456789abcdef" not in out and "FEDCBA9876543210" not in out
    assert "[ro.boot.hw.soc.id]: [REDACTED-ID-" in out
    assert "ceDataInode=0 deDataInode=0 pccCeDataInode=0 installed=true" in out
    assert "/data/resource-cache/com.android.systemui-accent-XXXX.frro" in out
    assert "Signing KeySets: 1" in out
    assert "Package [com.whatsapp] (f39ba71):" in out


def test_workmanager_tags_are_not_emails() -> None:
    tag = "u0a426 tag=*job*r/#IdentityHashWorker#@androidx.work.systemjobscheduler@com.facebook.katana/x.SystemJobService"
    assert [f for f in scan(tag) if f.category == "email"] == []
    assert Redactor().redact(tag) == tag
    assert [f.category for f in scan("owner=alice@mailbox.test\n")] == ["email"]


def test_carrier_ids_in_property_names_and_setup_date_are_normalised() -> None:
    text = (
        "[setupwizard.feature.show_pai_screen_in_main_flow.carrier1234]: [true]\n"
        "[com.google.android.setupwizard.complianceDate]: [2027-05-01]\n"
        "[ro.build.version.security_patch]: [2027-10-05]\n"
    )
    assert {f.category for f in scan(text)} == {"carrier_id", "setup_date"}
    out = Redactor().redact(text)
    assert "[setupwizard.feature.show_pai_screen_in_main_flow.carrier0]: [true]" in out
    assert "[com.google.android.setupwizard.complianceDate]: [2000-01-01]" in out
    assert "[ro.build.version.security_patch]: [2027-10-05]" in out  # build data: kept
    assert scan(out) == []
