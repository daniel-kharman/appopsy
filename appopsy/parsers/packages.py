"""Parser for `pm list packages` output.

Lines look like ``package:<name>``, with optional parts depending on flags:
``-f`` prefixes the APK path (``package:/data/app/.../base.apk=<name>``), ``-i``
appends ``installer=<pkg|null>`` and ``-U`` appends ``uid:<n>``.
"""

from __future__ import annotations

import re

from pydantic import BaseModel

from appopsy.parsers.base import ParseWarning

SOURCE = "pm list packages"

# Raw file names used by the packages collector. The redactor and the fixture
# scanner rely on SYSTEM_LIST_FILENAME to know which packages are system.
THIRD_PARTY_LIST_FILENAME = "pm-list-packages-3p.txt"
SYSTEM_LIST_FILENAME = "pm-list-packages-system.txt"

# `-f` paths can contain '=' (base64 segments), so the path is everything up to
# the last '=' that is followed by a package name.
_LINE = re.compile(
    r"^package:(?:(?P<path>\S+)=)?(?P<name>[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*)"
    r"(?P<rest>(?:\s+\S+)*)\s*$"
)
_INSTALLER = re.compile(r"\binstaller=(\S+)")
_UID = re.compile(r"\buid:(\d+)")


class PackageEntry(BaseModel):
    name: str
    installer: str | None = None  # None when not requested or reported as "null"
    uid: int | None = None
    apk_path: str | None = None


def parse_package_list(text: str) -> tuple[list[PackageEntry], list[ParseWarning]]:
    entries: list[PackageEntry] = []
    warnings: list[ParseWarning] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        m = _LINE.match(line)
        if not m:
            warnings.append(
                ParseWarning(source=SOURCE, line=lineno, text=line, message="not a package line")
            )
            continue
        rest = m["rest"]
        installer = _INSTALLER.search(rest)
        uid = _UID.search(rest)
        entries.append(
            PackageEntry(
                name=m["name"],
                installer=installer.group(1)
                if installer and installer.group(1) != "null"
                else None,
                uid=int(uid.group(1)) if uid else None,
                apk_path=m["path"],
            )
        )
    return entries, warnings
