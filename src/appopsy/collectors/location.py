"""Location: settings, providers and their last-known locations, per-app request
aggregates, GNSS state, geofences and the location event log.

One `dumpsys location` call (about 77 kB and 0.15 s on a Pixel 11 Pro).
"""

from __future__ import annotations

from appopsy.adb import Adb
from appopsy.case import Case
from appopsy.collectors import run_and_save

FILENAME = "dumpsys-location.txt"


def collect(adb: Adb, case: Case) -> None:
    run_and_save(adb, case, ["dumpsys", "location"], name=FILENAME, timeout=60)
