from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from appopsy.parsers.dumpsys_package import (
    PackageInfo,
    RuntimePermission,
    parse_dumpsys_package,
)

FIXTURES = Path(__file__).parent / "fixtures" / "17-google" / "capture-1"
FIXTURE = FIXTURES / "dumpsys-package-com.facebook.katana.txt"
SECTION_FIXTURE = FIXTURES / "dumpsys-package-packages.txt"
NORMALISED = datetime(2000, 1, 1)


@pytest.fixture(scope="module")
def facebook() -> PackageInfo:
    packages, warnings = parse_dumpsys_package(FIXTURE.read_text())
    assert warnings == []
    (pkg,) = packages  # only the Packages: section; Queries: has its own "User 0:" lines
    return pkg


def test_identity_and_version(facebook: PackageInfo) -> None:
    assert facebook.name == "com.facebook.katana"
    assert facebook.app_id == 10426
    assert facebook.version_code == 476015655
    assert facebook.version_name == "585.0.0.47.54"
    assert (facebook.min_sdk, facebook.target_sdk) == (30, 36)
    assert "HAS_CODE" in facebook.flags and "LARGE_HEAP" in facebook.flags
    assert not facebook.is_system


def test_install_source_and_times(facebook: PackageInfo) -> None:
    assert facebook.installer == "com.android.vending"
    assert facebook.update_owner == "com.android.vending"
    # Device-local wall-clock times; redact-fixture normalises them.
    assert facebook.timestamp == NORMALISED
    assert facebook.last_update_time == NORMALISED


def test_permission_lists(facebook: PackageInfo) -> None:
    assert len(facebook.requested_permissions) == 96
    assert "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION" in facebook.requested_permissions
    assert len(facebook.declared_permissions) == 7
    assert len(facebook.install_permissions) == 58
    assert all(p.granted for p in facebook.install_permissions[:1])


def test_user_state(facebook: PackageInfo) -> None:
    (user,) = facebook.users
    assert user.user_id == 0
    assert user.installed is True and user.hidden is False and user.stopped is False
    assert user.enabled == 0
    assert user.install_reason == 2
    assert user.first_install_time == NORMALISED
    assert user.data_dir == "/data/user/0/com.facebook.katana"
    assert len(user.disabled_components) == 13
    assert len(user.enabled_components) == 1328


def test_runtime_permissions(facebook: PackageInfo) -> None:
    perms = {p.name: p for p in facebook.runtime_permissions(user_id=0)}
    assert len(perms) == 21
    fine = perms["android.permission.ACCESS_FINE_LOCATION"]
    assert fine.granted and fine.user_set and not fine.user_fixed
    assert "USER_SENSITIVE_WHEN_GRANTED" in fine.flags
    audio = perms["android.permission.RECORD_AUDIO"]
    assert not audio.granted and not audio.user_set
    notifications = perms["android.permission.POST_NOTIFICATIONS"]
    assert not notifications.granted and notifications.user_fixed  # "Don't ask again"
    assert facebook.runtime_permissions(user_id=10) == []


def test_runtime_permission_has_no_appops_mode() -> None:
    """Grant state and appops mode are separate facts; the rules compare them.

    A permission can be granted while its op is 'foreground' or 'ignore' (and the
    background-location rule depends on exactly that gap), so the permission
    model must never carry or infer a mode.
    """
    assert set(RuntimePermission.model_fields) == {"name", "granted", "flags"}


MULTI = """\
Packages:
  Package [com.example.notes] (aaa1111):
    appId=10500
    versionCode=7 minSdk=26 targetSdk=35
    versionName=1.2
    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]
    timeStamp=2027-11-01 12:00:00
    lastUpdateTime=2027-11-01 12:00:12
    installerPackageName=null
    requested permissions:
      android.permission.ACCESS_BACKGROUND_LOCATION: restricted=true
      android.permission.CAMERA
    install permissions:
      android.permission.INTERNET: granted=true
      com.android.example.system#com.android.example.permission.ACCESS: granted=true
    User 0: ceDataInode=0 installed=true hidden=false suspended=false stopped=true notLaunched=true enabled=0
      firstInstallTime=2027-10-15 08:30:00
      runtime permissions:
        android.permission.CAMERA: granted=true, flags=[ USER_SET|ONE_TIME]
        android.permission.ACCESS_BACKGROUND_LOCATION: granted=false
        this line is not a permission
    User 10: ceDataInode=0 installed=false hidden=false suspended=false enabled=0
      runtime permissions:
        android.permission.CAMERA: granted=false, flags=[ ]
  Package [com.android.example.system] (bbb2222):
    appId=1000
    flags=[ SYSTEM HAS_CODE PERSISTENT ]
    User 0: installed=true
Hidden system packages:
  Package [com.android.example.system] (ccc3333):
    appId=1000
    flags=[ SYSTEM HAS_CODE ]
"""


def test_section_dump_with_several_packages_and_users() -> None:
    packages, warnings = parse_dumpsys_package(MULTI)
    notes, system = packages  # Hidden system packages are not current packages
    assert notes.name == "com.example.notes" and system.name == "com.android.example.system"
    assert system.is_system and not notes.is_system
    assert notes.installer is None  # "null"
    assert [p.name for p in notes.install_permissions][1] == (
        "com.android.example.system#com.android.example.permission.ACCESS"
    )
    assert notes.timestamp == datetime(2027, 11, 1, 12, 0, 0)
    assert notes.requested_permissions == [
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.CAMERA",
    ]
    owner, work = notes.users
    assert (owner.user_id, owner.stopped, owner.not_launched) == (0, True, True)
    assert owner.first_install_time == datetime(2027, 10, 15, 8, 30, 0)
    camera = notes.runtime_permissions(0)[0]
    assert camera.granted and camera.user_set and "ONE_TIME" in camera.flags
    background = notes.runtime_permissions(0)[1]
    assert not background.granted and background.flags == []
    assert (work.user_id, work.installed) == (10, False)
    assert [p.granted for p in notes.runtime_permissions(10)] == [False]
    assert [w.text.strip() for w in warnings] == ["this line is not a permission"]


def test_no_packages_section() -> None:
    packages, warnings = parse_dumpsys_package("Dexopt state:\n  [com.example.notes]\n")
    assert packages == []
    assert [w.message for w in warnings] == ["no Packages: section"]


def test_unparseable_scalars_become_warnings_not_crashes() -> None:
    text = (
        "Packages:\n  Package [com.example.notes] (aaa1111):\n"
        "    appId=abc\n    timeStamp=yesterday\n    versionCode=x minSdk=26\n"
    )
    (pkg,), warnings = parse_dumpsys_package(text)
    assert pkg.app_id is None and pkg.timestamp is None and pkg.version_code is None
    assert pkg.min_sdk == 26
    assert len(warnings) == 3


# --- `dumpsys package packages` (trimmed real capture) -----------------------


@pytest.fixture(scope="module")
def section() -> dict[str, PackageInfo]:
    packages, warnings = parse_dumpsys_package(SECTION_FIXTURE.read_text())
    assert warnings == []
    return {p.name: p for p in packages}


def test_section_fixture_packages(section: dict[str, PackageInfo]) -> None:
    # Hidden system packages (here: Play's factory copy) are not current packages.
    assert sorted(section) == sorted([
        "com.facebook.katana", "com.facebook.orca", "com.whatsapp", "com.tencent.mm",
        "com.twitter.android", "com.android.vending", "com.google.android.packageinstaller",
        "com.google.android.dialer", "com.google.android.apps.maps", "com.google.android.as",
    ])  # fmt: skip
    system = {n for n, p in section.items() if p.is_system}
    assert system == {
        "com.android.vending", "com.google.android.packageinstaller",
        "com.google.android.dialer", "com.google.android.apps.maps", "com.google.android.as",
    }  # fmt: skip
    assert section["com.google.android.packageinstaller"].installer is None


def test_section_matches_per_app_dump(
    section: dict[str, PackageInfo], facebook: PackageInfo
) -> None:
    """Same facts from one call as from the per-app dump, minus requested permissions."""
    fb = section["com.facebook.katana"]
    assert fb.requested_permissions == []  # the section form omits them
    assert facebook.requested_permissions  # the per-app form has them
    assert fb.runtime_permissions() == facebook.runtime_permissions()
    assert fb.install_permissions == facebook.install_permissions
    assert (fb.app_id, fb.version_code, fb.installer) == (
        facebook.app_id, facebook.version_code, facebook.installer,
    )  # fmt: skip


def test_shared_uid_app_has_no_own_permission_list(section: dict[str, PackageInfo]) -> None:
    maps = section["com.google.android.apps.maps"]
    assert maps.shared_user == "com.google.android.apps.maps"
    assert maps.runtime_permissions() == []  # held by the shared user, not "none"
    assert section["com.facebook.katana"].shared_user is None


def test_section_runtime_grants(section: dict[str, PackageInfo]) -> None:
    granted = {n: sum(r.granted for r in p.runtime_permissions()) for n, p in section.items()}
    assert granted["com.facebook.katana"] == 5
    assert granted["com.twitter.android"] == 1
    dialer = section["com.google.android.dialer"]
    assert len(dialer.runtime_permissions()) == 20
