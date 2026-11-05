from __future__ import annotations

from pathlib import Path

from appopsy.parsers.packages import parse_package_list

FIXTURES = Path(__file__).parent / "fixtures" / "17-google" / "capture-1"


def test_third_party_list_fixture() -> None:
    entries, warnings = parse_package_list((FIXTURES / "pm-list-packages-3p.txt").read_text())
    assert warnings == []
    by_name = {e.name: e for e in entries}
    assert set(by_name) == {
        "com.twitter.android", "com.facebook.katana", "com.facebook.orca",
        "com.whatsapp", "com.tencent.mm", "com.example.sideloaded",
    }  # fmt: skip
    assert by_name["com.whatsapp"].installer == "com.android.vending"
    assert by_name["com.example.sideloaded"].installer == "com.google.android.packageinstaller"
    assert all(e.uid is None and e.apk_path is None for e in entries)


def test_system_list_fixture() -> None:
    entries, warnings = parse_package_list((FIXTURES / "pm-list-packages-system.txt").read_text())
    assert warnings == []
    names = {e.name for e in entries}
    assert len(names) == len(entries) > 300
    assert {"android", "com.android.vending", "com.google.android.packageinstaller"} <= names
    assert all(e.installer is None for e in entries)


def test_flags_f_i_u_and_null_installer() -> None:
    text = (
        "package:/data/app/~~AbC-12_x==/com.example.notes-Zz9==/base.apk=com.example.notes"
        "  installer=null uid:10234\n"
        "package:com.example.sideloaded  installer=com.google.android.packageinstaller\n"
        "\n"
        "Error: something odd\n"
    )
    entries, warnings = parse_package_list(text)
    notes, side = entries
    assert notes.name == "com.example.notes"
    assert notes.apk_path == "/data/app/~~AbC-12_x==/com.example.notes-Zz9==/base.apk"
    assert notes.installer is None
    assert notes.uid == 10234
    assert side.installer == "com.google.android.packageinstaller"
    assert [w.line for w in warnings] == [4]
