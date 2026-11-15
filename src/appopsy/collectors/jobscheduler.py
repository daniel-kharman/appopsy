"""Scheduled jobs: every app's registered jobs with their constraints, worker
class names (WorkManager tags), last run times, and quota / controller state.

One `dumpsys jobscheduler` call (about 3.6 MB and 0.25 s on a Pixel 11 Pro).
"""

from __future__ import annotations

from appopsy.adb import Adb
from appopsy.case import Case
from appopsy.collectors import run_and_save

FILENAME = "dumpsys-jobscheduler.txt"


def collect(adb: Adb, case: Case) -> None:
    run_and_save(adb, case, ["dumpsys", "jobscheduler"], name=FILENAME, timeout=60)
