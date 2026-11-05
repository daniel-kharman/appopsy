from __future__ import annotations

from pathlib import Path

import pytest

from appopsy.parsers.dumpsys_package import (
    SharedUser,
    parse_dumpsys_package,
    parse_shared_users,
    runtime_permissions_for,
)

FIXTURES = Path(__file__).parent / "fixtures" / "17-google" / "capture-1"


@pytest.fixture(scope="module")
def shared() -> dict[str, SharedUser]:
    users, warnings = parse_shared_users(
        (FIXTURES / "dumpsys-package-shared-users.txt").read_text()
    )
    assert warnings == []
    return {u.name: u for u in users}


def test_entries(shared: dict[str, SharedUser]) -> None:
    assert sorted(shared) == ["android.media", "android.uid.se", "com.google.android.apps.maps"]
    media = shared["android.media"]
    assert media.app_id == 10114
    assert media.packages == [
        "com.android.soundpicker", "com.android.providers.downloads.ui",
        "com.android.providers.downloads", "com.android.mtp",
    ]  # fmt: skip
    assert len(media.install_permissions) == 28
    assert [p.granted for p in media.runtime_permissions()] == [True, True, True]
    assert "SYSTEM_FIXED" in media.runtime_permissions()[0].flags


def test_entry_without_runtime_permissions(shared: dict[str, SharedUser]) -> None:
    se = shared["android.uid.se"]
    assert se.packages == ["com.android.se"]
    assert len(se.install_permissions) == 2
    assert [u.user_id for u in se.users] == [0]
    assert se.runtime_permissions() == []


def test_shared_uid_package_gets_its_permissions_from_the_shared_user(
    shared: dict[str, SharedUser],
) -> None:
    packages, _ = parse_dumpsys_package((FIXTURES / "dumpsys-package-packages.txt").read_text())
    by = {p.name: p for p in packages}
    maps = by["com.google.android.apps.maps"]
    assert maps.runtime_permissions() == []  # its own block has none...
    perms = {p.name: p for p in runtime_permissions_for(maps, shared)}
    assert (
        len(perms) == 17 and sum(p.granted for p in perms.values()) == 13
    )  # ...the shared user does
    assert perms["android.permission.ACCESS_BACKGROUND_LOCATION"].granted
    assert perms["android.permission.ACCESS_BACKGROUND_LOCATION"].user_set
    assert not perms["android.permission.BLUETOOTH_CONNECT"].granted
    # A package without a shared UID keeps its own list.
    fb = by["com.facebook.katana"]
    assert runtime_permissions_for(fb, shared) == fb.runtime_permissions()


def test_unknown_shared_user_returns_none_not_empty() -> None:
    """Missing shared-user data must be distinguishable from 'no permissions'."""
    packages, _ = parse_dumpsys_package((FIXTURES / "dumpsys-package-packages.txt").read_text())
    maps = next(p for p in packages if p.name == "com.google.android.apps.maps")
    assert runtime_permissions_for(maps, {}) is None


def test_no_section_and_bad_lines() -> None:
    assert parse_shared_users("Packages:\n")[1][0].message == "no Shared users: section"
    users, warnings = parse_shared_users(
        "Shared users:\n  SharedUser [x.y] (a1):\n    appId=z\n    User 0: \n      runtime permissions:\n"
        "        garbage\n  not an entry\n"
    )
    assert users[0].app_id is None and users[0].runtime_permissions() == []
    assert len(warnings) == 3
