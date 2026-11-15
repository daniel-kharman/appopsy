"""Collectors: run allowlisted adb commands and save the raw output to a case folder.

Collectors don't parse. A command that fails (timeout, non-zero exit, device
quirk) is recorded in the manifest and the run carries on. A refused command is
a bug in appopsy, not a device problem, so CommandRefusedError propagates.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from appopsy.adb import Adb, AdbError, CommandRefusedError
from appopsy.case import Case

Collector = Callable[[Adb, Case], None]


def run_and_save(
    adb: Adb,
    case: Case,
    command: Sequence[str],
    *,
    name: str | None = None,
    timeout: float | None = None,
) -> str | None:
    """Run one shell command and save its output. Returns the output, or None on failure."""
    started = case.clock()
    try:
        output = adb.shell(*command, timeout=timeout)
    except CommandRefusedError:
        raise
    except AdbError as exc:
        case.record_failure(command, str(exc), started=started, finished=case.clock())
        return None
    case.write_raw(command, output, started=started, finished=case.clock(), name=name)
    return output
