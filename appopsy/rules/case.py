"""Parsed view of one case folder (or capture fixture) for the rules.

Every source is optional: a missing or unparseable file leaves its part empty and
is recorded in ``warnings``, so rules that don't need it still run.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import cached_property
from pathlib import Path
from typing import TypeVar

from appopsy.collectors.alarm import FILENAME as ALARM_FILE
from appopsy.collectors.appops import FILENAME as APPOPS_FILE
from appopsy.collectors.dumpsys_package import FILENAME as PACKAGES_FILE
from appopsy.collectors.getprop import FILENAME as GETPROP_FILE
from appopsy.collectors.jobscheduler import FILENAME as JOBSCHEDULER_FILE
from appopsy.collectors.launcher import FILENAME as LAUNCHER_FILE
from appopsy.collectors.location import FILENAME as LOCATION_FILE
from appopsy.parsers.alarm import AlarmSnapshot, parse_alarms
from appopsy.parsers.appops import AppOpsSnapshot, UidLink, link_uids, parse_appops
from appopsy.parsers.base import ParseWarning
from appopsy.parsers.date import EPOCH_FILENAME, LOCAL_FILENAME, DeviceClock, parse_device_clock
from appopsy.parsers.dumpsys_package import PackageInfo, parse_dumpsys_package
from appopsy.parsers.getprop import DeviceInfo, device_info, parse_getprop
from appopsy.parsers.jobscheduler import JobSchedulerSnapshot, parse_jobscheduler
from appopsy.parsers.launcher import LauncherActivity, parse_launcher
from appopsy.parsers.location import LocationSnapshot, parse_location
from appopsy.parsers.packages import (
    SYSTEM_LIST_FILENAME,
    THIRD_PARTY_LIST_FILENAME,
    PackageEntry,
    parse_package_list,
)
from appopsy.rules.engine import AppClass, EvidenceRef

T = TypeVar("T")


class CaseData:
    def __init__(self, raw_dir: Path) -> None:
        self.raw_dir = raw_dir
        self.warnings: list[ParseWarning] = []

    def _parse(
        self, name: str, parse: Callable[[str], tuple[T, list[ParseWarning]]], empty: T
    ) -> T:
        path = self.raw_dir / name
        if not path.exists():
            return empty
        value, warnings = parse(path.read_text(encoding="utf-8", errors="replace"))
        self.warnings += warnings
        return value

    @cached_property
    def device(self) -> DeviceInfo:
        none: dict[str, str] = {}
        return device_info(self._parse(GETPROP_FILE, parse_getprop, none))

    @cached_property
    def clock(self) -> DeviceClock | None:
        epoch, local = self.raw_dir / EPOCH_FILENAME, self.raw_dir / LOCAL_FILENAME
        if not epoch.exists():
            return None
        clock, warnings = parse_device_clock(
            epoch.read_text(encoding="utf-8"),
            local.read_text(encoding="utf-8") if local.exists() else "",
        )
        self.warnings += warnings
        return clock

    @cached_property
    def installers(self) -> dict[str, str | None]:
        """Third-party package -> installer package (None when not reported)."""
        none: list[PackageEntry] = []
        entries = self._parse(THIRD_PARTY_LIST_FILENAME, parse_package_list, none)
        return {e.name: e.installer for e in entries}

    @cached_property
    def third_party(self) -> set[str]:
        return set(self.installers)

    @cached_property
    def system(self) -> set[str]:
        none: list[PackageEntry] = []
        entries = self._parse(SYSTEM_LIST_FILENAME, parse_package_list, none)
        return {e.name for e in entries}

    @cached_property
    def packages(self) -> dict[str, PackageInfo]:
        none: list[PackageInfo] = []
        infos = self._parse(PACKAGES_FILE, parse_dumpsys_package, none)
        return {p.name: p for p in infos}

    @cached_property
    def appops(self) -> AppOpsSnapshot:
        return self._parse(APPOPS_FILE, parse_appops, AppOpsSnapshot())

    @cached_property
    def uid_links(self) -> dict[tuple[int, str], UidLink]:
        """(UID, package) -> how that UID relates to the package (see ``link_uids``)."""
        app_ids = {name: info.app_id for name, info in self.packages.items()}
        return {(lk.uid, lk.package): lk for lk in link_uids(self.appops, app_ids)}

    @cached_property
    def jobs(self) -> JobSchedulerSnapshot:
        return self._parse(JOBSCHEDULER_FILE, parse_jobscheduler, JobSchedulerSnapshot())

    @cached_property
    def alarms(self) -> AlarmSnapshot:
        return self._parse(ALARM_FILE, parse_alarms, AlarmSnapshot())

    @cached_property
    def location(self) -> LocationSnapshot:
        return self._parse(LOCATION_FILE, parse_location, LocationSnapshot())

    @cached_property
    def launcher(self) -> set[str]:
        """Packages with a launcher icon (empty for cases collected before this source)."""
        none: list[LauncherActivity] = []
        return {a.package for a in self._parse(LAUNCHER_FILE, parse_launcher, none)}

    def classify(self, package: str) -> AppClass:
        """user_installed (pm list -3); for system packages (pm list -s / SYSTEM flag):
        preinstalled if it has a launcher icon (an app you use, e.g. Maps), else system
        (a platform component, e.g. android, Play services); otherwise unknown."""
        if package in self.third_party:
            return "user_installed"
        info = self.packages.get(package)
        if package in self.system or package == "android" or (info is not None and info.is_system):
            return "preinstalled" if package in self.launcher else "system"
        return "unknown"

    @staticmethod
    def evidence(file: str, start: int | None, end: int | None = None) -> list[EvidenceRef]:
        if start is None:
            return []
        return [EvidenceRef(file=file, start=start, end=end if end is not None else start)]
