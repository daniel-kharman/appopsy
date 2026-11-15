"""Package details for every installed package: `dumpsys package packages` and
`dumpsys package shared-users`.

One call returns the ``Packages:`` section for all packages (system included),
with runtime permission grants, install permissions, versions, installer and
per-user state. It omits ``requested permissions:``; per-app
``dumpsys package <pkg>`` (also allowlisted) has them if a rule ever needs them.
Apps that share a UID have their runtime permissions under the shared user, not
in their own block, so the ``Shared users:`` section is collected too.
See docs/format-notes.md for the measurements behind this choice.
"""

from __future__ import annotations

from appopsy.adb import Adb
from appopsy.case import Case
from appopsy.collectors import run_and_save

FILENAME = "dumpsys-package-packages.txt"
SHARED_USERS_FILENAME = "dumpsys-package-shared-users.txt"


def collect(adb: Adb, case: Case) -> None:
    run_and_save(adb, case, ["dumpsys", "package", "packages"], name=FILENAME, timeout=120)
    run_and_save(
        adb, case, ["dumpsys", "package", "shared-users"], name=SHARED_USERS_FILENAME, timeout=60
    )
