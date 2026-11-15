"""Device clock, used to turn relative times (``+1m39s241ms``) into absolute ones.

Two commands: the epoch (unambiguous) and local ISO time with UTC offset. The
manifest records host UTC before and after each, which bounds clock skew
between the device and the computer.
"""

from __future__ import annotations

from appopsy.adb import Adb
from appopsy.case import Case
from appopsy.collectors import run_and_save
from appopsy.parsers.date import EPOCH_FILENAME, LOCAL_FILENAME

LOCAL_FORMAT = "+%Y-%m-%dT%H:%M:%S%z"


def collect(adb: Adb, case: Case) -> None:
    run_and_save(adb, case, ["date", "+%s"], name=EPOCH_FILENAME)
    run_and_save(adb, case, ["date", LOCAL_FORMAT], name=LOCAL_FILENAME)
