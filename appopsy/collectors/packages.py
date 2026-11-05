"""Installed packages: third-party apps with their installer, and the system list.

The system list isn't needed by the privacy rules directly, but it is how the
redactor and the fixture scanner tell system packages from third-party ones.
"""

from __future__ import annotations

from appopsy.adb import Adb
from appopsy.case import Case
from appopsy.collectors import run_and_save
from appopsy.parsers.packages import SYSTEM_LIST_FILENAME, THIRD_PARTY_LIST_FILENAME


def collect(adb: Adb, case: Case) -> None:
    run_and_save(adb, case, ["pm", "list", "packages", "-3", "-i"], name=THIRD_PARTY_LIST_FILENAME)
    run_and_save(adb, case, ["pm", "list", "packages", "-s"], name=SYSTEM_LIST_FILENAME)
