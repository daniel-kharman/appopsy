"""Alarms: pending alarms per app (RTC / RTC_WAKEUP / ELAPSED), per-app wakeup
statistics, and recent deliveries.

One `dumpsys alarm` call (about 180 kB and 0.1 s on a Pixel 11 Pro).
"""

from __future__ import annotations

from appopsy.adb import Adb
from appopsy.case import Case
from appopsy.collectors import run_and_save

FILENAME = "dumpsys-alarm.txt"


def collect(adb: Adb, case: Case) -> None:
    run_and_save(adb, case, ["dumpsys", "alarm"], name=FILENAME, timeout=60)
