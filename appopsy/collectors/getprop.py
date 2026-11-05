"""System properties: model, Android version, security patch level, timezone."""

from __future__ import annotations

from appopsy.adb import Adb
from appopsy.case import Case
from appopsy.collectors import run_and_save

FILENAME = "getprop.txt"


def collect(adb: Adb, case: Case) -> None:
    run_and_save(adb, case, ["getprop"], name=FILENAME)
