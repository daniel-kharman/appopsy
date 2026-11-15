"""Launcher activities: which packages have an icon in the app drawer.

One `pm query-activities --brief -a android.intent.action.MAIN -c
android.intent.category.LAUNCHER` call (about 21 kB and 0.15 s on a Pixel 11 Pro).
It tells preinstalled apps people use (Maps, Phone) from platform components
(android, Play services). It lists every app with an icon, third-party ones too,
so fixtures go through the package policy like the dumpsys files.
"""

from __future__ import annotations

from appopsy.adb import LAUNCHER_QUERY, Adb
from appopsy.case import Case
from appopsy.collectors import run_and_save

FILENAME = "pm-query-launcher.txt"
COMMAND = list(LAUNCHER_QUERY)


def collect(adb: Adb, case: Case) -> None:
    run_and_save(adb, case, COMMAND, name=FILENAME, timeout=60)
