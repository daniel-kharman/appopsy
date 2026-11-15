"""Parser for `dumpsys alarm`: pending alarms and per-app wakeup statistics.

`chatty-wakeups` compares an app's wakeups per hour with a threshold. The counts
come from the per-app blocks under `Alarm Stats:` (`u0a426:<pkg> +5s256ms
running, 24 wakeups:`, then one entry per alarm tag) and the window from
`Runtime uptime (elapsed)`, i.e. since boot.

A zero running time is printed as `0`, not `+0ms`.

Times are device-local wall clock without an offset.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from pydantic import BaseModel

from appopsy.parsers.base import ParseWarning, parse_duration, parse_uid_label

SOURCE = "dumpsys alarm"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"

_NOW = re.compile(r"^\s+nowRTC=-?\d+=(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})\b")
_UPTIME = re.compile(r"^\s+Runtime uptime \(elapsed\): (?P<d>\+\S+)$")
_PENDING_HEADER = re.compile(r"^  \d+ pending alarms:\s*$")
_ENTRY = re.compile(
    r"^    (?P<type>[A-Z_]+) #\d+: Alarm\{[0-9a-f]+ type \d+ origWhen -?\d+ "
    r"whenElapsed -?\d+ (?P<pkg>[\w.]+)\}$"
)
_DETAIL = re.compile(
    r"^\s+type=\S+ origWhen=(?P<when>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}|\S+) "
    r"window=(?P<window>\S+)(?: exactAllowReason=\S+)? repeatInterval=(?P<repeat>\d+) "
    r"count=(?P<count>\d+) flags=(?P<flags>\S+)"
)
_STATS_HEADER = re.compile(
    r"^  (?P<label>u\d+[a-z]\d+|\d+):(?P<pkg>[\w.]+) (?P<run>\+\S+|0) running, (?P<w>\d+) wakeups:$"
)
_STATS_ENTRY = re.compile(
    r"^    (?P<run>\+\S+|0) (?P<w>\d+) wakes (?P<a>\d+) alarms, last (?P<last>-\S+):$"
)


class PendingAlarm(BaseModel):
    line: int | None = None
    type: str  # RTC, RTC_WAKEUP, ELAPSED, ELAPSED_WAKEUP
    package: str
    tag: str | None = None
    orig_when: datetime | None = None  # wall-clock trigger time (RTC types)
    orig_when_in: timedelta | None = None  # relative trigger time (ELAPSED types)
    window: timedelta | None = None
    repeat_interval: timedelta | None = None
    count: int | None = None
    flags: str | None = None

    @property
    def wakeup(self) -> bool:
        return self.type.endswith("_WAKEUP")


class AlarmTagStats(BaseModel):
    line: int | None = None  # the tag line
    tag: str
    running: timedelta
    wakeups: int
    alarms: int
    last_ago: timedelta


class AppAlarmStats(BaseModel):
    line: int | None = None
    end_line: int | None = None
    label: str
    uid: int
    package: str
    running: timedelta
    wakeups: int
    tags: list[AlarmTagStats] = []


class AlarmSnapshot(BaseModel):
    now: datetime | None = None
    runtime_elapsed: timedelta | None = None  # the window the stats cover (since boot)
    pending: list[PendingAlarm] = []
    stats: list[AppAlarmStats] = []

    def stats_for(self, package: str) -> AppAlarmStats | None:
        return next((s for s in self.stats if s.package == package), None)

    def wakeups_per_hour(self, package: str) -> float | None:
        stats = self.stats_for(package)
        if stats is None or not self.runtime_elapsed:
            return None
        return stats.wakeups / (self.runtime_elapsed.total_seconds() / 3600)


def _window(value: str) -> timedelta | None:
    return timedelta(0) if value == "0" else parse_duration(value)


def parse_alarms(text: str) -> tuple[AlarmSnapshot, list[ParseWarning]]:
    warnings: list[ParseWarning] = []
    snap = AlarmSnapshot()

    def warn(lineno: int, line: str, message: str) -> None:
        warnings.append(ParseWarning(source=SOURCE, line=lineno, text=line, message=message))

    region: str | None = None  # "pending" | "stats" | None
    alarm: PendingAlarm | None = None
    app: AppAlarmStats | None = None
    entry: tuple[timedelta, int, int, timedelta] | None = None
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if m := _NOW.match(line):
            snap.now = datetime.strptime(m["ts"], TIME_FORMAT)
        elif m := _UPTIME.match(line):
            snap.runtime_elapsed = parse_duration(m["d"])
        if indent <= 2:
            if _PENDING_HEADER.match(line):
                region, alarm = "pending", None
                continue
            if line.strip() == "Alarm Stats:":
                region, app = "stats", None
                continue
            if region == "stats" and (m := _STATS_HEADER.match(line)):
                ids = parse_uid_label(m["label"])
                app = AppAlarmStats(label=m["label"], uid=ids[0] if ids else -1, package=m["pkg"],
                                    running=parse_duration(m["run"]) or timedelta(0),
                                    wakeups=int(m["w"]), line=lineno,
                                    end_line=lineno)  # fmt: skip
                snap.stats.append(app)
                continue
            if region == "stats" and re.match(r"^  (?:u\d+[a-z]\d+|\d+):\S+ ", line):
                warn(lineno, line, "unrecognised stats line")
                app = None
                continue
            region = None
            continue
        if region == "pending":
            if m := _ENTRY.match(line):
                alarm = PendingAlarm(type=m["type"], package=m["pkg"], line=lineno)
                snap.pending.append(alarm)
            elif alarm is not None and line.strip().startswith("tag="):
                alarm.tag = line.strip().removeprefix("tag=")
            elif alarm is not None and (m := _DETAIL.match(line)):
                when = m["when"]
                try:
                    alarm.orig_when = datetime.strptime(when, TIME_FORMAT)
                except ValueError:
                    alarm.orig_when_in = parse_duration(when)
                    if alarm.orig_when_in is None:
                        warn(lineno, line, "unrecognised alarm line")
                alarm.window = _window(m["window"])
                alarm.repeat_interval = timedelta(milliseconds=int(m["repeat"]))
                alarm.count = int(m["count"])
                alarm.flags = m["flags"]
        elif region == "stats" and app is not None:
            if m := _STATS_ENTRY.match(line):
                entry = (parse_duration(m["run"]) or timedelta(0), int(m["w"]), int(m["a"]),
                         abs(parse_duration(m["last"]) or timedelta(0)))  # fmt: skip
            elif entry is not None and indent >= 6:
                running, wakeups, alarms, last = entry
                tag = AlarmTagStats(tag=line.strip(), running=running, wakeups=wakeups,
                                    alarms=alarms, last_ago=last, line=lineno)  # fmt: skip
                app.tags.append(tag)
                app.end_line = lineno
                entry = None
    return snap, warnings
