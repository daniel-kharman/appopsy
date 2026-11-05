"""Parser for `pm query-activities --brief` (launcher activities).

`<n> activities found:`, then one block per activity: `  Activity #<i>:`, a
`priority=... isDefault=...` line and the component `<pkg>/<activity>`. Only the
component matters: a package with one is an app with an icon in the drawer.
"""

from __future__ import annotations

import re

from pydantic import BaseModel

from appopsy.parsers.base import ParseWarning

SOURCE = "pm query-activities (launcher)"

_HEADER = re.compile(r"^(?P<n>\d+) activities found:$")
_ACTIVITY = re.compile(r"^  Activity #\d+:$")
_DETAIL = re.compile(r"^    priority=-?\d+ .*$")
_COMPONENT = re.compile(r"^    (?P<pkg>[A-Za-z][\w]*(?:\.[\w]+)*)/(?P<activity>[\w.$]+)$")


class LauncherActivity(BaseModel):
    line: int | None = None
    package: str
    activity: str  # as printed: ".Main" or a full class name


def parse_launcher(text: str) -> tuple[list[LauncherActivity], list[ParseWarning]]:
    warnings: list[ParseWarning] = []
    activities: list[LauncherActivity] = []
    expected: int | None = None
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or _ACTIVITY.match(line) or _DETAIL.match(line):
            continue
        if m := _HEADER.match(line):
            expected = int(m["n"])
        elif m := _COMPONENT.match(line):
            activities.append(
                LauncherActivity(package=m["pkg"], activity=m["activity"], line=lineno)
            )
        else:
            warnings.append(ParseWarning(source=SOURCE, line=lineno, text=line,
                                         message="unrecognised launcher line"))  # fmt: skip
    if expected is not None and expected != len(activities):
        warnings.append(ParseWarning(
            source=SOURCE, message=f"header says {expected} activities, found {len(activities)}"
        ))  # fmt: skip
    return activities, warnings
