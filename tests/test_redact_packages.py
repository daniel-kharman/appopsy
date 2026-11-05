"""Package policy on synthetic data.

Only com.example.* / org.example.* names (which can't be published on Play) are
used for disallowed apps, so no real app list can end up in this file.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from appopsy import cli, redact
from appopsy.redact import Finding, Redactor, redact_tree, scan
from appopsy.redact_packages import (
    DEFAULT_ALLOWLIST,
    AllowedPackage,
    PackagePolicy,
    load_allowlist,
)

SYSTEM = "package:android\npackage:com.android.vending\npackage:com.google.android.gms\npackage:com.google.android.packageinstaller\n"
THIRD_PARTY = (
    "package:com.example.bank  installer=com.android.vending\n"
    "package:com.whatsapp  installer=com.android.vending\n"
    "package:org.example.diary  installer=org.example.store\n"
    "package:com.facebook.katana  installer=org.example.store\n"
)

DUMPSYS = """\
Packages:
  Package [com.facebook.katana] (f39ba71):
    pkg=Package{f39ba71 com.facebook.katana}
    codePath=/data/app/~~AbCdEfGhIjKlMnOpQrStUv==/com.facebook.katana-vUtSrQpOnMlKjIhGfEdCbA==
    queriesPackages=[com.google.android.gms, com.example.bank, com.whatsapp, com.example.unlisted]
    timeStamp=2027-11-01 12:00:00
    lastUpdateTime=2027-11-01 12:00:12
    installerPackageName=com.android.vending
    User 0: ceDataInode=1 installed=true
      firstInstallTime=2027-10-15 08:30:00
    shareTarget=com.example.bank.ShareActivity
    helper=com.facebook.katana.example.bank.Thing

Domain verification status:
  com.facebook.katana:
    ID: 339c5228-8c7f-44e7-a3b8-884ef50ebdf8

Queries:
  system apps queryable: false
  queries via package name:
    com.example.bank:
      com.facebook.katana
      com.whatsapp
    com.facebook.katana:
      com.google.android.gms
      org.example.diary
      com.example.unlisted
  queryable via interaction:
    User 0:
      [android,com.example.bank,com.google.android.gms]:
        com.facebook.katana
      [com.example.bank,org.example.diary]:
        com.facebook.katana

Dexopt state:
  [com.facebook.katana]
"""


def make_redactor(**kw: object) -> Redactor:
    r = Redactor(**kw)  # type: ignore[arg-type]
    r.harvest(SYSTEM, "pm-list-packages-system.txt")
    r.harvest(THIRD_PARTY, "pm-list-packages-3p.txt")
    return r


def test_third_party_list_becomes_the_allowlist() -> None:
    out = make_redactor().redact(THIRD_PARTY)
    assert out.splitlines() == [
        "package:com.whatsapp  installer=com.android.vending",
        # Allowed app installed by a non-allowed store: installer becomes canonical.
        "package:com.facebook.katana  installer=com.android.vending",
        "package:com.twitter.android  installer=com.android.vending",
        "package:com.facebook.orca  installer=com.android.vending",
        "package:com.tencent.mm  installer=com.android.vending",
        "package:com.example.sideloaded  installer=com.google.android.packageinstaller",
    ]


def test_system_list_is_unchanged() -> None:
    assert make_redactor().redact(SYSTEM) == SYSTEM


def test_added_lines_mimic_flags() -> None:
    r = make_redactor()
    text = "package:/data/app/~~x==/com.example.bank-y==/base.apk=com.example.bank  installer=com.android.vending uid:10234\n"
    lines = r.redact(text).splitlines()
    assert len(lines) == 6
    assert lines[-1] == (
        "package:/data/app/com.example.sideloaded/base.apk=com.example.sideloaded"
        "  installer=com.google.android.packageinstaller uid:19005"
    )


def test_dumpsys_package_is_filtered_and_normalised() -> None:
    r = make_redactor()
    out = r.redact(DUMPSYS)
    for name in [
        "com.example.bank",
        "org.example.diary",
        "com.example.unlisted",
        "org.example.store",
    ]:
        assert name not in out, name
    assert "queriesPackages=[com.google.android.gms, com.whatsapp]" in out
    assert "codePath=/data/app/~~REDACTED==/com.facebook.katana-REDACTED==" in out
    assert "timeStamp=2000-01-01 00:00:00" in out
    assert "lastUpdateTime=2000-01-01 00:00:00" in out
    assert "firstInstallTime=2000-01-01 00:00:00" in out
    assert "ID: 00000000-0000-0000-0000-000000000001" in out
    # A line naming a known third-party app outside a structural position is removed...
    assert "shareTarget=" not in out
    # ...but an allowed package's own class that merely contains the text is kept.
    assert "helper=com.facebook.katana.example.bank.Thing" in out
    # Queries: headers for removed packages go with their children; lists are filtered.
    queries = out.split("Queries:\n", 1)[1].split("\nDexopt", 1)[0]
    assert queries == (
        "  system apps queryable: false\n"
        "  queries via package name:\n"
        "    com.facebook.katana:\n"
        "      com.google.android.gms\n"
        "  queryable via interaction:\n"
        "    User 0:\n"
        "      [android,com.google.android.gms]:\n"
        "        com.facebook.katana\n"
    )
    assert scan(out, r.packages) == []
    assert "Package [com.facebook.katana]" in out and "[com.facebook.katana]" in out


def test_scan_reports_disallowed_packages_at_structural_positions() -> None:
    policy = PackagePolicy()
    policy.harvest("pm-list-packages-system.txt", SYSTEM)
    found = {pkg for _, pkg in policy.scan(THIRD_PARTY)}
    assert found == {"com.example.bank", "org.example.diary", "org.example.store"}
    dumpsys_found = {pkg for _, pkg in policy.scan(DUMPSYS)}
    assert {"com.example.bank", "org.example.diary", "com.example.unlisted"} <= dumpsys_found


def test_without_system_list_everything_unlisted_is_third_party() -> None:
    r = Redactor()
    r.harvest(THIRD_PARTY, "pm-list-packages-3p.txt")
    out = r.redact(DUMPSYS)
    assert "com.google.android.gms" not in out.split("Queries:", 1)[1]
    assert not r.packages.system_known


def test_custom_allowlist(tmp_path: Path) -> None:
    path = tmp_path / "allow.txt"
    path.write_text(
        "# mine\ncom.example.notes\ncom.example.side  com.google.android.packageinstaller\n"
    )
    allow = load_allowlist(path)
    assert allow == (
        AllowedPackage("com.example.notes"),
        AllowedPackage("com.example.side", "com.google.android.packageinstaller"),
    )
    r = make_redactor(packages=PackagePolicy(allowlist=allow))
    r.harvest(SYSTEM, "pm-list-packages-system.txt")
    assert r.redact(THIRD_PARTY).splitlines() == [
        "package:com.example.notes  installer=com.android.vending",
        "package:com.example.side  installer=com.google.android.packageinstaller",
    ]


@pytest.mark.parametrize("line", ["com.example.notes extra words", "not a package!"])
def test_bad_allowlist_lines(tmp_path: Path, line: str) -> None:
    path = tmp_path / "allow.txt"
    path.write_text(line + "\n")
    with pytest.raises(ValueError, match="Bad allowlist line"):
        load_allowlist(path)


def test_default_allowlist() -> None:
    names = [a.name for a in DEFAULT_ALLOWLIST]
    assert names == [
        "com.twitter.android", "com.facebook.katana", "com.facebook.orca",
        "com.whatsapp", "com.tencent.mm", "com.example.sideloaded",
    ]  # fmt: skip
    assert [a.installer for a in DEFAULT_ALLOWLIST if a.installer != "com.android.vending"] == [
        "com.google.android.packageinstaller"
    ]


def test_redact_tree_writes_nothing_when_output_is_dirty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = tmp_path / "raw"
    src.mkdir()
    (src / "a.txt").write_text("fine\n")
    (src / "b.txt").write_text("also fine\n")
    leftover = Finding("package", "com.example.bank", 1)
    monkeypatch.setattr(
        redact, "scan", lambda text, packages=None, name="": [leftover] if "also" in text else []
    )
    out = tmp_path / "out"
    result = redact_tree([src], out, Redactor())
    assert [f for _, f in result.remaining] == [leftover]
    assert result.written == []
    assert not out.exists()


runner = CliRunner()


def test_cli_packages_option_and_check(tmp_path: Path) -> None:
    src = tmp_path / "raw"
    src.mkdir()
    (src / "pm-list-packages-system.txt").write_text(SYSTEM)
    (src / "pm-list-packages-3p.txt").write_text(THIRD_PARTY)
    (src / "dumpsys-package-com.facebook.katana.txt").write_text(DUMPSYS)

    dirty = runner.invoke(cli.app, ["redact-fixture", "--check", str(src)])
    assert dirty.exit_code == 1
    assert "com.example.bank" not in dirty.output  # masked

    out = tmp_path / "fixture"
    done = runner.invoke(cli.app, ["redact-fixture", str(src), "--out", str(out)])
    assert done.exit_code == 0, done.output
    assert runner.invoke(cli.app, ["redact-fixture", "--check", str(out)]).exit_code == 0

    allow = tmp_path / "allow.txt"
    allow.write_text("com.example.bank\n")
    custom = runner.invoke(
        cli.app, ["redact-fixture", "--check", "--packages", str(allow), str(out)]
    )
    assert custom.exit_code == 1  # default-allowlisted apps now count as disallowed


def test_null_installer_is_not_a_package() -> None:
    r = make_redactor()
    text = "Packages:\n  Package [com.google.android.gms] (a1):\n    installerPackageName=null\n"
    assert r.redact(text) == text
    assert r.packages.scan(text) == []


SHARED_USERS = """\
Shared users:
  SharedUser [android.uid.example] (a1):
    appId=1000
    Packages
      PackageSetting{b2 com.google.android.gms/1000}
    User 0:
      runtime permissions:
        android.permission.CAMERA: granted=true, flags=[ USER_SET]
  SharedUser [org.example.vendor.shared] (c3):
    appId=10440
    Packages
      PackageSetting{d4 com.example.bank/10440}
    install permissions:
      org.example.vendor.permission.SYNC: granted=true
    User 0:
      gids=[3003]
  SharedUser [org.example.orphan] (e5):
    appId=10441
"""


def test_shared_user_entry_with_a_disallowed_member_goes_whole() -> None:
    r = make_redactor()
    out = r.redact(SHARED_USERS)
    assert out == SHARED_USERS.split("  SharedUser [org.example.vendor.shared]")[0]
    for leak in ["org.example.vendor", "com.example.bank", "org.example.orphan"]:
        assert leak not in out
    assert r.packages.scan(out) == []


def test_scan_flags_disallowed_and_unattributable_shared_users() -> None:
    policy = PackagePolicy()
    policy.harvest("pm-list-packages-system.txt", SYSTEM)
    found = {pkg for _, pkg in policy.scan(SHARED_USERS)}
    assert found == {"com.example.bank", "org.example.orphan"}


APPOPS = """\
AppOps Uid Op State
  Uid u0a426:
    state=top
      FINE_LOCATION: mode=foreground
    Package com.facebook.katana:
      FINE_LOCATION (allow):
        null=[
          Access: [top-s] 2027-11-12 09:15:00.250 (-638ms)
          Reject: [bg-s]2027-11-12 08:52:30.400 (-21m14s536ms)
        ]
  Uid u0a500:
    state=cch
      FINE_LOCATION: mode=foreground
    Package com.example.bank:
      FINE_LOCATION (allow):
        null=[
          Reject: [bg-s]2027-11-12 08:52:30.400 (-21m14s536ms)
        ]
  Uid u0a501:
    state=cch
      CAMERA: mode=ignore
  Uid 1000:
    Package android:
      WAKE_LOCK (allow):
        null=[
          Access: [pers-s] 2027-11-01 10:00:01.000 (-16d1h) proxy[uid=10426, pkg=com.facebook.katana, attributionTag=null]
          Access: [pers-s] 2027-11-01 10:00:02.000 (-16d1h) proxy[uid=10500, pkg=com.example.bank, attributionTag=null]
        ]
----Location, Microphone, and Camera App Ops (Last 1 Hour)----
UID|PACKAGE_NAME|DEVICE_ID|OP_NAME|ATTRIBUTION_TAG|ACCESS_TIME|ACCESS_COUNTS|REJECT_COUNTS|DURATION|UID_STATE|OP_FLAGS|ATTRIBUTION_CHAIN_ID|ATTRIBUTION_FLAGS
10426|com.facebook.katana|default:0|FINE_LOCATION|null|2027-11-12 09:15:00.250|1|0|0|top|s|-1|0
10500|com.example.bank|default:0|FINE_LOCATION|null|2027-11-12 08:52:30.400|0|1|0|bg|s|-1|0
"""


def test_appops_uid_blocks_rows_and_proxies() -> None:
    r = make_redactor()
    r.harvest("package:android\n", "pm-list-packages-system.txt")
    r.harvest("1826007300\n", "date-epoch.txt")  # a capture clock, so times can be shifted
    out = r.redact(APPOPS)
    assert "com.example.bank" not in out
    assert "Uid u0a500:" not in out  # whole block: its history would still point at the app
    assert "Uid u0a426:" in out and "Package com.facebook.katana:" in out
    assert "Uid u0a501:" in out  # UID-level modes only: nothing identifying
    assert "proxy[uid=10426, pkg=com.facebook.katana" in out
    assert "10426|com.facebook.katana|" in out and "10500|" not in out
    assert r.packages.scan(out) == []


def test_scan_flags_appops_package_positions() -> None:
    policy = PackagePolicy()
    policy.harvest("pm-list-packages-system.txt", SYSTEM + "package:android\n")
    found = [(line, pkg) for line, pkg in policy.scan(APPOPS)]
    assert {pkg for _, pkg in found} == {"com.example.bank"}
    assert len(found) == 3  # Package line, proxy, table row
