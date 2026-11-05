"""AppOps state: per-UID modes, per-package modes, and the last allowed (Access)
and denied (Reject) attempt for each op in each UID state.

One `dumpsys appops` call covers every app (about 2 MB and 0.25 s on a Pixel 11
Pro), so per-package `cmd appops get` calls aren't needed for a snapshot. The
output's relative times (``(-3m12s890ms)``) change on every call; parsers use the
absolute timestamps and the device clock.
"""

from __future__ import annotations

from appopsy.adb import Adb
from appopsy.case import Case
from appopsy.collectors import run_and_save

FILENAME = "dumpsys-appops.txt"


def collect(adb: Adb, case: Case) -> None:
    run_and_save(adb, case, ["dumpsys", "appops"], name=FILENAME, timeout=60)
