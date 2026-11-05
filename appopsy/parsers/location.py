"""Parser for `dumpsys location`: settings, providers, per-app aggregates, event log.

The per-app aggregates (`<uid>/<pkg>: min/max interval = ..., total/active/
foreground duration = ..., locations = N`) say how long each app held location
requests, and how much of that was while it was in the foreground: input for
`sensor-use-summary`. Some listener requests are `hiddenFromAppOps`, so their
location use doesn't show in appops at all; that is recorded.

Location values themselves aren't modelled: fixtures carry only
`Location[<provider> REDACTED]`, and no rule needs them. Event-log times are
year-less (`MM-DD HH:MM:SS.mmm`) and kept as printed.
"""

from __future__ import annotations

import re
from datetime import timedelta

from pydantic import BaseModel

from appopsy.parsers.base import ParseWarning, parse_duration

SOURCE = "dumpsys location"

_WHO = r"(?P<uid>\d+)/(?P<pkg>[\w.]+)(?:\[(?P<tag>[^\]]*)\])?"
_LISTENER = re.compile(rf"^\s+{_WHO}/\S+ (?P<req>Request\[.*)$")
_AGGREGATE = re.compile(
    rf"^\s+{_WHO}: min/max interval = (?P<min>\S+)/(?P<max>\S+), "
    r"total/active/foreground duration = (?P<total>\S+)/(?P<active>\S+)/(?P<fg>\S+), "
    r"locations = (?P<n>\d+)$"
)
_EVENT = re.compile(r"^\s+(?P<stamp>\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}): (?P<rest>.*)$")
_EVENT_KINDS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^(?P<prov>\w+) provider request = (?P<detail>.*)$"), "request"),
    (re.compile(rf"^(?P<prov>\w+) provider (?P<sign>[+-])registration {_WHO}"), "registration"),
    (
        re.compile(rf"^(?P<prov>gnss measurements) (?P<sign>[+-])registration {_WHO}"),
        "registration",
    ),
    (
        re.compile(rf"^(?P<prov>\w+) provider delivered location\[(?P<n>\d+)\] to {_WHO}"),
        "delivered",
    ),
    (re.compile(r"^(?P<prov>\w+) provider received location\[(?P<n>\d+)\]"), "received"),
)


def _duration(value: str) -> timedelta | None:
    return timedelta(0) if value == "0" else parse_duration(value)


class LocationListener(BaseModel):
    line: int | None = None
    uid: int
    package: str
    tag: str | None = None
    request: str
    hidden_from_appops: bool = False


class ProviderState(BaseModel):
    name: str
    enabled: bool | None = None
    allowed: bool | None = None
    last_location_redacted: bool | None = None  # a last location exists (values not kept)
    listeners: list[LocationListener] = []


class LocationAggregate(BaseModel):
    line: int | None = None
    provider: str
    uid: int
    package: str
    tag: str | None = None
    min_interval: str  # e.g. "5s", "21600s" or "passive"
    max_interval: str
    total: timedelta
    active: timedelta
    foreground: timedelta
    locations: int

    @property
    def background(self) -> timedelta:
        return self.total - self.foreground


class LocationEvent(BaseModel):
    line: int | None = None
    stamp: str  # year-less local time as printed, e.g. "12-31 23:00:29.059"
    provider: str  # gps, network, fused, passive, gnss_measurements
    kind: str  # request, +registration, -registration, delivered, received, other
    count: int | None = None  # locations in a delivery
    uid: int | None = None
    package: str | None = None
    detail: str | None = None


class LocationSnapshot(BaseModel):
    enabled: bool | None = None
    providers: list[ProviderState] = []
    aggregates: list[LocationAggregate] = []
    events: list[LocationEvent] = []

    def aggregates_for(self, package: str) -> list[LocationAggregate]:
        return [a for a in self.aggregates if a.package == package]


def _event(stamp: str, rest: str) -> LocationEvent:
    for rx, kind in _EVENT_KINDS:
        if m := rx.match(rest):
            groups = m.groupdict()
            return LocationEvent(
                stamp=stamp,
                provider=groups["prov"].replace(" ", "_"),
                kind=f"{groups['sign']}registration" if kind == "registration" else kind,
                count=int(groups["n"]) if groups.get("n") else None,
                uid=int(groups["uid"]) if groups.get("uid") else None,
                package=groups.get("pkg"),
                detail=groups.get("detail"),
            )
    return LocationEvent(stamp=stamp, provider=rest.split(" ", 1)[0], kind="other", detail=rest)


def parse_location(text: str) -> tuple[LocationSnapshot, list[ParseWarning]]:
    warnings: list[ParseWarning] = []
    snap = LocationSnapshot()

    def warn(lineno: int, line: str, message: str) -> None:
        warnings.append(ParseWarning(source=SOURCE, line=lineno, text=line, message=message))

    section: str | None = None  # the indent-2 section we are in
    provider: ProviderState | None = None
    agg_provider: str | None = None
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if indent <= 2:
            section, provider, agg_provider = stripped, None, None
            continue
        if stripped.startswith("Location Setting: "):
            snap.enabled = stripped.endswith("true")
        elif section == "Location Providers:":
            if m := re.match(r"^    (\w+) provider:$", line):
                provider = ProviderState(name=m.group(1))
                snap.providers.append(provider)
            elif provider is not None:
                if stripped in ("enabled=true", "enabled=false"):
                    provider.enabled = stripped == "enabled=true"
                elif stripped in ("allowed=true", "allowed=false"):
                    provider.allowed = stripped == "allowed=true"
                elif stripped.startswith("last location=Location["):
                    provider.last_location_redacted = "REDACTED]" in stripped
                elif m := _LISTENER.match(line):
                    provider.listeners.append(LocationListener(
                        uid=int(m["uid"]), package=m["pkg"], tag=m["tag"], request=m["req"],
                        hidden_from_appops="hiddenFromAppOps" in m["req"], line=lineno,
                    ))  # fmt: skip
        elif section == "Historical Aggregate Location Provider Data:":
            if m := re.match(r"^    (\w+):$", line):
                agg_provider = m.group(1)
            elif agg_provider is not None and (m := _AGGREGATE.match(line)):
                total, active, fg = (
                    _duration(m["total"]),
                    _duration(m["active"]),
                    _duration(m["fg"]),
                )
                if total is None or active is None or fg is None:
                    warn(lineno, line, "unrecognised aggregate line")
                    continue
                snap.aggregates.append(LocationAggregate(
                    provider=agg_provider, uid=int(m["uid"]), package=m["pkg"], tag=m["tag"],
                    min_interval=m["min"], max_interval=m["max"], total=total, active=active,
                    foreground=fg, locations=int(m["n"]), line=lineno,
                ))  # fmt: skip
            else:
                warn(lineno, line, "unrecognised aggregate line")
        elif section == "Event Log:" and (m := _EVENT.match(line)):
            event = _event(m["stamp"], m["rest"])
            event.line = lineno
            snap.events.append(event)
    return snap, warnings
