"""Parser for `dumpsys appops`: modes, and the last access / reject per UID state.

Two layers, kept apart:

- **UID-level modes** (``      OP: mode=foreground`` directly under ``Uid ...:``) are
  the effective policy when set. :meth:`UidOps.effective_mode` applies them.
- **Package-level ops** (``      OP (allow):`` under ``Package ...:``) carry the
  package's own mode and the events: one ``Access:`` / ``Reject:`` line per UID
  state, never just one per op.

Op *categories* matter for location. FINE_LOCATION / COARSE_LOCATION events are
the evidence that a location was delivered (Access) or denied (Reject).
MONITOR_LOCATION / MONITOR_HIGH_POWER_LOCATION only record that the app had an
active location *request*, and GPS that the GPS engine ran for it. A background
MONITOR_* access is not "location received in the background"; rules must use
:attr:`OpCategory.LOCATION_DELIVERY` events for that.

Runtime permission grants are a different source and model
(:mod:`appopsy.parsers.dumpsys_package`); the gap between a grant and its mode is
what the rules look at.

Times are device-local wall clock without an offset (UTC in shifted fixtures);
the relative ``(-21m14s536ms)`` part changes on every call and is not kept.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel

from appopsy.parsers.base import ParseWarning, parse_duration, parse_uid_label

SOURCE = "dumpsys appops"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
# Process states treated as "the app wasn't in use". fgsvc (foreground service)
# counts as foreground for while-in-use permissions, so it isn't here.
BACKGROUND_STATES = frozenset({"bg", "cch"})


class OpCategory(StrEnum):
    LOCATION_DELIVERY = "location_delivery"  # FINE/COARSE: location delivered or denied
    LOCATION_REQUEST = "location_request"  # MONITOR_*: an active request, not a delivery
    LOCATION_HARDWARE = "location_hardware"  # GPS: the GPS engine ran for the app
    OTHER = "other"


_CATEGORIES = {
    "FINE_LOCATION": OpCategory.LOCATION_DELIVERY,
    "COARSE_LOCATION": OpCategory.LOCATION_DELIVERY,
    "MONITOR_LOCATION": OpCategory.LOCATION_REQUEST,
    "MONITOR_HIGH_POWER_LOCATION": OpCategory.LOCATION_REQUEST,
    "GPS": OpCategory.LOCATION_HARDWARE,
}


def op_category(op: str) -> OpCategory:
    return _CATEGORIES.get(op, OpCategory.OTHER)


class Proxy(BaseModel):
    uid: int
    package: str
    attribution_tag: str | None = None


class OpEvent(BaseModel):
    line: int | None = None
    kind: Literal["access", "reject"]
    uid_state: str  # top, fg, fgsvc, bg, cch, pers, ...
    attribution: str  # s = self, tp/tpd = trusted proxy/proxied, up/upd = untrusted
    time: datetime  # device-local wall clock
    duration: timedelta | None = None
    attribution_tag: str | None = None
    proxy: Proxy | None = None

    @property
    def in_background(self) -> bool:
        return self.uid_state in BACKGROUND_STATES


class PackageOp(BaseModel):
    line: int | None = None
    op: str
    mode: str  # the package-level mode
    switch_op: str | None = None  # e.g. MONITOR_LOCATION is governed by COARSE_LOCATION
    switch_mode: str | None = None
    events: list[OpEvent] = []
    # Still in progress when dumped ("Running start at: +13h49m29s269ms"): how long.
    running_for: timedelta | None = None
    # Overlapping starts of a running op ("startNesting=4"); printed only when > 1.
    running_nesting: int | None = None

    @property
    def category(self) -> OpCategory:
        return op_category(self.op)


class PackageOps(BaseModel):
    line: int | None = None  # the `Package <name>:` line
    name: str
    ops: list[PackageOp] = []

    def op(self, name: str) -> PackageOp | None:
        return next((o for o in self.ops if o.op == name), None)

    def events(self, category: OpCategory) -> list[tuple[str, OpEvent]]:
        return [(o.op, e) for o in self.ops if o.category is category for e in o.events]


class UidOps(BaseModel):
    label: str  # as printed: u0a426, 1000
    uid: int
    user_id: int
    app_id: int
    state: str | None = None
    capability: str | None = None
    attributes: dict[str, str] = {}
    modes: dict[str, str] = {}  # UID-level modes: the effective policy where set
    mode_lines: dict[str, int] = {}  # op -> line of its UID-level mode (evidence)
    line: int | None = None
    packages: list[PackageOps] = []

    def effective_mode(self, op: PackageOp) -> str:
        """The UID-level mode for the op (or its switch op) if set, else the package's."""
        key = op.switch_op or op.op
        if key in self.modes:
            return self.modes[key]
        return op.switch_mode or op.mode


class RecentOp(BaseModel):
    """A row of "Location, Microphone, and Camera App Ops (Last 1 Hour)"."""

    uid: int
    package: str
    device_id: str
    op: str
    attribution_tag: str | None
    access_time: datetime
    access_count: int
    reject_count: int
    duration: timedelta
    uid_state: str
    op_flags: str
    attribution_chain_id: int
    attribution_flags: int


class AppOpsSnapshot(BaseModel):
    uids: list[UidOps] = []
    recent: list[RecentOp] = []

    def uid(self, uid: int) -> UidOps | None:
        return next((u for u in self.uids if u.uid == uid), None)

    def for_package(self, package: str) -> list[UidOps]:
        return [u for u in self.uids if any(p.name == package for p in u.packages)]


class UidRole(StrEnum):
    PRIMARY = "primary"  # the package's own app id
    SECONDARY = "secondary"  # another UID that runs code for the package
    UNKNOWN = "unknown"  # the package's own app id isn't known


class UidLink(BaseModel):
    """One package seen under one appops UID, and how that UID relates to it.

    A package can appear under a UID other than its own: on the Pixel 11 Pro,
    com.google.android.as (app id 10168) also appears under UID 30168, which runs a
    com.google.android.as process but is owned by no package. Reports must label
    such a UID as a secondary UID of the package, never as a separate app.
    """

    uid: int
    label: str
    package: str
    role: UidRole
    owner_uid: int | None = None  # the package's primary UID for this user, if known

    @property
    def display_name(self) -> str:
        if self.role is UidRole.SECONDARY:
            return f"{self.package} (secondary UID {self.uid})"
        return self.package


def link_uids(snapshot: AppOpsSnapshot, app_ids: Mapping[str, int | None]) -> list[UidLink]:
    """Classify every (UID, package) pair against each package's own app id.

    ``app_ids`` maps package name -> app id, e.g. from ``dumpsys package packages``
    (``{p.name: p.app_id for p in packages}``). Deliberately no arithmetic on UIDs:
    a UID is primary only if its app id *is* the package's, secondary if it isn't,
    and unknown if the package's app id wasn't collected.
    """
    links: list[UidLink] = []
    for uid in snapshot.uids:
        for pkg in uid.packages:
            own = app_ids.get(pkg.name)
            if own is None:
                role, owner = UidRole.UNKNOWN, None
            elif own == uid.app_id:
                role, owner = UidRole.PRIMARY, uid.uid
            else:
                role, owner = UidRole.SECONDARY, uid.user_id * 100000 + own
            links.append(
                UidLink(uid=uid.uid, label=uid.label, package=pkg.name, role=role, owner_uid=owner)
            )
    return links


# --- Parsing ----------------------------------------------------------------

_UID_HEADER = re.compile(r"^  Uid (?P<label>\S+):$")
_UID_MODE = re.compile(r"^      (?P<op>[A-Z0-9_]+): mode=(?P<mode>\w+)$")
_PACKAGE = re.compile(r"^    Package (?P<name>[A-Za-z][\w.]*):$")
_PACKAGE_OP = re.compile(
    r"^      (?P<op>[A-Z0-9_]+) \((?P<mode>\w+)"
    r"(?: / switch (?P<sop>[A-Z0-9_]+)=(?P<smode>\w+))?\):\s*$"
)
_RUNNING = re.compile(r"^          Running start at: (?P<dur>\+[0-9dhms]+)$")
_NESTING = re.compile(r"^          startNesting=(?P<n>\d+)$")
_TAG_OPEN = re.compile(r"^        (?P<tag>\S+)=\[$")
_TAG_CLOSE = re.compile(r"^        \]$")
_EVENT = re.compile(
    r"^          (?P<kind>Access|Reject): \[(?P<state>[a-z]+)-(?P<attr>[a-z]+)\] ?"
    r"(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) \([^)]*\)"
    r"(?: duration=(?P<dur>\+[0-9dhms]+))?"
    r"(?: proxy\[uid=(?P<puid>\d+), pkg=(?P<ppkg>[^,\]]+), attributionTag=(?P<ptag>[^\]]*)\])?"
    r"\s*$"
)
_ATTRIBUTE = re.compile(r"^    (?P<k>\w+)=(?P<v>.*)$")
_TABLE_HEADER = "UID|PACKAGE_NAME|"


class _Parser:
    def __init__(self) -> None:
        self.warnings: list[ParseWarning] = []

    def warn(self, lineno: int, text: str, message: str) -> None:
        self.warnings.append(ParseWarning(source=SOURCE, line=lineno, text=text, message=message))

    def event(self, m: re.Match[str], tag: str | None) -> OpEvent:
        proxy = None
        if m["puid"]:
            ptag = m["ptag"].strip()
            proxy = Proxy(
                uid=int(m["puid"]),
                package=m["ppkg"].strip(),
                attribution_tag=None if ptag in ("", "null") else ptag,
            )
        return OpEvent(
            kind="access" if m["kind"] == "Access" else "reject",
            uid_state=m["state"],
            attribution=m["attr"],
            time=datetime.strptime(m["ts"], TIME_FORMAT),
            duration=parse_duration(m["dur"]) if m["dur"] else None,
            attribution_tag=tag,
            proxy=proxy,
        )

    def uid_section(self, lines: list[tuple[int, str]]) -> list[UidOps]:
        uids: list[UidOps] = []
        uid: UidOps | None = None
        package: PackageOps | None = None
        op: PackageOp | None = None
        tag: str | None = None
        for lineno, line in lines:
            if not line.strip():
                continue
            if m := _UID_HEADER.match(line):
                parsed = parse_uid_label(m["label"])
                if parsed is None:
                    self.warn(lineno, line, "unrecognised UID label")
                    uid = None
                    continue
                uid = UidOps(
                    label=m["label"],
                    uid=parsed[0],
                    user_id=parsed[1],
                    app_id=parsed[2],
                    line=lineno,
                )
                uids.append(uid)
                package = op = None
                continue
            if uid is None:
                self.warn(lineno, line, "expected 'Uid <label>:'")
                continue
            if m := _PACKAGE.match(line):
                package = PackageOps(name=m["name"], line=lineno)
                uid.packages.append(package)
                op = None
            elif package is None and (m := _UID_MODE.match(line)):
                uid.modes[m["op"]] = m["mode"]
                uid.mode_lines[m["op"]] = lineno
            elif package is None and (m := _ATTRIBUTE.match(line)):
                if m["k"] == "state":
                    uid.state = m["v"]
                elif m["k"] == "capability":
                    uid.capability = m["v"]
                else:
                    uid.attributes[m["k"]] = m["v"]
            elif package is not None and (m := _PACKAGE_OP.match(line)):
                op = PackageOp(
                    op=m["op"],
                    mode=m["mode"],
                    switch_op=m["sop"],
                    switch_mode=m["smode"],
                    line=lineno,
                )
                package.ops.append(op)
                tag = None
            elif op is not None and (m := _TAG_OPEN.match(line)):
                tag = None if m["tag"] == "null" else m["tag"]
            elif op is not None and _TAG_CLOSE.match(line):
                tag = None
            elif op is not None and (m := _EVENT.match(line)):
                event = self.event(m, tag)
                event.line = lineno
                op.events.append(event)
            elif op is not None and (m := _RUNNING.match(line)):
                op.running_for = parse_duration(m["dur"])
            elif op is not None and (m := _NESTING.match(line)):
                op.running_nesting = int(m["n"])
            else:
                self.warn(lineno, line, "unrecognised line in UID block")
        return uids

    def table_row(self, lineno: int, line: str) -> RecentOp | None:
        f = line.split("|")
        try:
            if len(f) != 13:
                raise ValueError("expected 13 fields")
            return RecentOp(
                uid=int(f[0]),
                package=f[1],
                device_id=f[2],
                op=f[3],
                attribution_tag=None if f[4] == "null" else f[4],
                access_time=datetime.strptime(f[5], TIME_FORMAT),
                access_count=int(f[6]),
                reject_count=int(f[7]),
                duration=timedelta(milliseconds=int(f[8])),
                uid_state=f[9],
                op_flags=f[10],
                attribution_chain_id=int(f[11]),
                attribution_flags=int(f[12]),
            )
        except ValueError as exc:
            self.warn(lineno, line, f"bad recent-ops row: {exc}")
            return None


def parse_appops(text: str) -> tuple[AppOpsSnapshot, list[ParseWarning]]:
    parser = _Parser()
    snapshot = AppOpsSnapshot()
    uid_lines: list[tuple[int, str]] = []
    section: str | None = None
    in_table = False
    found_uids = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line and not line[0].isspace():  # top-level line
            if line.startswith(_TABLE_HEADER):
                in_table = True
                continue
            if in_table and "|" in line:
                if row := parser.table_row(lineno, line):
                    snapshot.recent.append(row)
                continue
            in_table = False
            section = line.rstrip()
            found_uids = found_uids or section == "AppOps Uid Op State"
            continue
        if section == "AppOps Uid Op State":
            uid_lines.append((lineno, line))
    if not found_uids:
        parser.warn(0, "", "no AppOps Uid Op State section")
        parser.warnings[-1].line = None
    snapshot.uids = parser.uid_section(uid_lines)
    return snapshot, parser.warnings
