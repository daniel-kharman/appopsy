"""CI guard: committed fixtures must not contain personal identifiers.

Fails if anything under tests/fixtures/ contains a serial, IMEI/ICCID, email,
MAC or phone number (or the other categories the redactor knows) that is not
one of the redactor's placeholders, or names a third-party package that is not
on the default allowlist. Values are masked in the failure message so a leak
isn't repeated in CI logs.
"""

from __future__ import annotations

from pathlib import Path

from appopsy.parsers.date import EPOCH_FILENAME, LOCAL_FILENAME
from appopsy.parsers.packages import SYSTEM_LIST_FILENAME, THIRD_PARTY_LIST_FILENAME
from appopsy.redact import mask, scan_tree
from appopsy.redact_time import ANCHOR, ANCHOR_EPOCH

FIXTURES = Path(__file__).parent / "fixtures"
REQUIRED = {"serial", "imei", "email", "mac", "phone", "package"}


def test_fixtures_contain_no_identifiers() -> None:
    findings = scan_tree([FIXTURES]) if FIXTURES.exists() else []
    report = [
        f"{p.relative_to(FIXTURES)}:{f.line} {f.category} {mask(f.value)}" for p, f in findings
    ]
    assert report == [], (
        "Unredacted identifiers in fixtures; run `appopsy redact-fixture`:\n" + "\n".join(report)
    )


def _fixture_folders() -> list[Path]:
    """Every folder under tests/fixtures/ that directly holds fixture files."""
    return sorted({p.parent for p in FIXTURES.rglob("*.txt")} - {FIXTURES}, key=lambda p: str(p))


def test_every_real_fixture_folder_is_a_capture_folder() -> None:
    """One capture per folder, with its own clock and package lists (see CLAUDE.md).

    The clock is what redact-fixture shifts every timestamp by, and the system
    list is how the scanner tells system packages from third-party ones.
    """
    required = {EPOCH_FILENAME, LOCAL_FILENAME, SYSTEM_LIST_FILENAME, THIRD_PARTY_LIST_FILENAME}
    for folder in _fixture_folders():
        if folder.name.startswith("synthetic-"):
            continue
        names = {f.name for f in folder.iterdir()}
        missing = required - names
        assert not missing, f"{folder.relative_to(FIXTURES)} is missing {sorted(missing)}"


def test_capture_clocks_sit_on_the_anchor() -> None:
    for folder in _fixture_folders():
        if folder.name.startswith("synthetic-"):
            continue
        assert (folder / EPOCH_FILENAME).read_text().strip() == str(ANCHOR_EPOCH), folder
        assert (folder / LOCAL_FILENAME).read_text().strip() == ANCHOR.strftime(
            "%Y-%m-%dT%H:%M:%S+0000"
        ), folder


def test_scanner_would_catch_a_leak(tmp_path: Path) -> None:
    """The guard above is only meaningful if the scanner detects each required category."""
    (tmp_path / SYSTEM_LIST_FILENAME).write_text("package:android\npackage:com.android.vending\n")
    (tmp_path / "pm-list-packages-3p.txt").write_text(
        "package:com.whatsapp  installer=com.android.vending\n"
        "package:com.example.bank  installer=com.android.vending\n"
    )
    (tmp_path / "dumpsys-package-com.whatsapp.txt").write_text(
        "Queries:\n  queries via package name:\n    org.example.diary:\n      com.whatsapp\n"
    )
    (tmp_path / "leak.txt").write_text(
        "[ro.serialno]: [ZZ123ABC456]\n"
        "imei=353456789012348\n"
        "owner=alice@mailbox.test\n"
        "mac=a4:5e:60:12:34:56\n"
        "tel:+61491570156\n"
    )
    findings = scan_tree([tmp_path])
    found = {f.category for _, f in findings}
    assert found >= REQUIRED, f"scanner missed: {REQUIRED - found}"
    packages = {f.value for _, f in findings if f.category == "package"}
    assert packages == {"com.example.bank", "org.example.diary"}
