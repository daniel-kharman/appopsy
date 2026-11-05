"""Parser for `dumpsys jobscheduler`: registered jobs and recently completed jobs.

Each registered job gives its owner, WorkManager worker class (when it is one),
service, constraints, periodicity and last run times: what
`unconstrained-background-work` needs. A job is unconstrained when it requires
neither charging, nor device idle, nor an unmetered network: "any network" is not
a constraint (mobile data will do).

Times (`Last successful run:`) are device-local wall clock without an offset.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from pydantic import BaseModel

from appopsy.parsers.base import ParseWarning, parse_duration, parse_uid_label

SOURCE = "dumpsys jobscheduler"
WORKMANAGER_NAMESPACE = "androidx.work.systemjobscheduler"
_NETWORK_TYPE = re.compile(r"^\s+Network type: (?P<v>unmetered|any|NetworkRequest \[.*)$")

_PLAIN_HEADER = re.compile(
    r"^  JOB #(?P<label>[^/\s]+)/(?P<id>-?\d+): [0-9a-f]+ (?P<pkg>[\w.]+)/(?P<svc>\S+)$"
)
_NS_HEADER = re.compile(
    r"^  JOB (?P<ns>[\w.]+):(?P<label>[^/\s]+)/(?P<id>-?\d+): [0-9a-f]+ (?P<tag>\S+)$"
)
_TAG_TARGET = re.compile(r"@(?P<pkg>[\w.]+)/(?P<svc>\S+)$")
_TAG_WORKER = re.compile(r"^#(?P<worker>[^#]+)#")
_COMPLETED_HEADER = re.compile(r"^  (?P<ago>[+-](?:\d+(?:ms|[dhms]))+)$")
_COMPLETED_JOB = re.compile(
    r"^\s+[0-9a-f]+ (?:\{(?P<ns>[^}]*)\} )?#(?P<label>[^/\s]+)/(?P<id>-?\d+) (?P<target>\S+)$"
)
_SOURCE_LINE = re.compile(r"^\s+Source: uid=\S+ user=\d+ pkg=(?P<pkg>[\w.]+)$")
_CONSTRAINTS = re.compile(
    r"^\s+(?P<kind>Required|Satisfied|Unsatisfied) constraints:(?P<list>[A-Z_ ]*)"
)
_REQUIRES = re.compile(
    r"charging=(?P<c>true|false) batteryNotLow=(?P<b>true|false) deviceIdle=(?P<i>true|false)"
)
_PERIODIC = re.compile(r"^\s+PERIODIC: interval=(?P<i>\S+) flex=(?P<f>\S+)")
_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


class Job(BaseModel):
    line: int | None = None  # first line of the job block (evidence)
    end_line: int | None = None
    label: str  # as printed: u0a426, 1000
    uid: int
    user_id: int
    app_id: int
    namespace: str | None = None
    job_id: str  # app-chosen; a capture-scoped placeholder in fixtures
    package: str
    service: str
    worker: str | None = None  # WorkManager worker class, e.g. StoryTrayPredictionPrefetchWorker
    priority: int | None = None
    required: list[str] = []
    satisfied: list[str] = []
    unsatisfied: list[str] = []
    requires_charging: bool | None = None
    requires_battery_not_low: bool | None = None
    requires_device_idle: bool | None = None
    periodic_interval: timedelta | None = None
    periodic_flex: timedelta | None = None
    minimum_latency: timedelta | None = None
    standby_bucket: str | None = None
    # "none" (no connectivity constraint), "any", "unmetered", or "unknown" when the
    # job needs connectivity but the dump doesn't say which kind.
    network: str = "none"
    last_successful_run: datetime | None = None
    last_failed_run: datetime | None = None

    @property
    def is_workmanager(self) -> bool:
        return self.namespace == WORKMANAGER_NAMESPACE

    @property
    def is_unconstrained(self) -> bool | None:
        """Requires neither charging, device idle nor an unmetered network.

        None when that can't be told: the job needs a network but the dump doesn't
        say whether an unmetered one.
        """
        if self.requires_charging or "CHARGING" in self.required:
            return False
        if self.requires_device_idle or "IDLE" in self.required:
            return False
        if self.network == "unmetered":
            return False
        return None if self.network == "unknown" else True

    @property
    def requirements(self) -> list[str]:
        """What the job does require, in plain terms, for the report."""
        out = [c for c in self.required if c not in ("FLEXIBILITY",)]
        if self.network in ("any", "unmetered"):
            out = [
                ("ANY_NETWORK" if self.network == "any" else "UNMETERED_NETWORK")
                if c == "CONNECTIVITY"
                else c
                for c in out
            ]
        return out


class CompletedJob(BaseModel):
    line: int | None = None
    ago: timedelta
    label: str
    job_id: str
    package: str | None = None
    worker: str | None = None


class JobSchedulerSnapshot(BaseModel):
    jobs: list[Job] = []
    completed: list[CompletedJob] = []

    def for_package(self, package: str) -> list[Job]:
        return [j for j in self.jobs if j.package == package]


def _sections(text: str) -> dict[str, list[tuple[int, str]]]:
    out: dict[str, list[tuple[int, str]]] = {}
    current: list[tuple[int, str]] | None = None
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.strip() and not line[0].isspace():
            current = out.setdefault(line.rstrip(), [])
            continue
        if current is not None:
            current.append((lineno, line))
    return out


def _blocks(lines: list[tuple[int, str]], start: re.Pattern[str]) -> list[list[tuple[int, str]]]:
    blocks: list[list[tuple[int, str]]] = []
    for item in lines:
        if start.match(item[1]):
            blocks.append([item])
        elif blocks:
            blocks[-1].append(item)
    return blocks


def _target(tag: str) -> tuple[str | None, str | None, str | None]:
    """(package, service, worker) from a job tag or `pkg/service`."""
    worker = m.group("worker") if (m := _TAG_WORKER.match(tag)) else None
    if t := _TAG_TARGET.search(tag):
        return t["pkg"], t["svc"], worker
    if "/" in tag and not tag.startswith("#"):
        pkg, _, svc = tag.partition("/")
        return pkg, svc, worker
    return None, None, worker


class _Parser:
    def __init__(self) -> None:
        self.warnings: list[ParseWarning] = []

    def warn(self, lineno: int, text: str, message: str) -> None:
        self.warnings.append(ParseWarning(source=SOURCE, line=lineno, text=text, message=message))

    def duration(self, lineno: int, line: str, value: str) -> timedelta | None:
        d = parse_duration(value)
        if d is None:
            self.warn(lineno, line, "unrecognised duration")
        return d

    def job(self, block: list[tuple[int, str]]) -> Job | None:
        lineno, header = block[0]
        if m := _PLAIN_HEADER.match(header):
            namespace, pkg, svc, worker = None, m["pkg"], m["svc"], None
        elif m := _NS_HEADER.match(header):
            namespace = m["ns"]
            pkg, svc, worker = _target(m["tag"])
        else:
            self.warn(lineno, header, "unrecognised job header")
            return None
        ids = parse_uid_label(m["label"])
        if ids is None or pkg is None or svc is None:
            self.warn(lineno, header, "unrecognised job header")
            return None
        job = Job(label=m["label"], uid=ids[0], user_id=ids[1], app_id=ids[2], namespace=namespace,
                  job_id=m["id"], package=pkg, service=svc, worker=worker,
                  line=lineno, end_line=block[-1][0])  # fmt: skip
        for n, line in block[1:]:
            s = line.strip()
            if src := _SOURCE_LINE.match(line):
                job.package = src["pkg"]
            elif s.startswith("Service: ") and "/" in s:
                owner, _, service = s.removeprefix("Service: ").partition("/")
                job.service = owner + service if service.startswith(".") else service
            elif s.startswith("Priority: "):
                job.priority = int(s.split()[1]) if s.split()[1].isdigit() else None
            elif s.startswith("Requires: ") and (r := _REQUIRES.search(s)):
                job.requires_charging = r["c"] == "true"
                job.requires_battery_not_low = r["b"] == "true"
                job.requires_device_idle = r["i"] == "true"
            elif c := _CONSTRAINTS.match(line):
                setattr(job, c["kind"].lower(), c["list"].split())
            elif nt := _NETWORK_TYPE.match(line):
                v = nt["v"]
                job.network = (
                    v
                    if v in ("unmetered", "any")
                    else ("unmetered" if "NOT_METERED" in v else "any")
                )
            elif p := _PERIODIC.match(line):
                job.periodic_interval = self.duration(n, line, p["i"])
                job.periodic_flex = self.duration(n, line, p["f"])
            elif s.startswith("Minimum latency: "):
                job.minimum_latency = self.duration(n, line, s.removeprefix("Minimum latency: "))
            elif s.startswith("Standby bucket: "):
                job.standby_bucket = s.removeprefix("Standby bucket: ")
            elif s.startswith(("Last successful run: ", "Last failed run: ")):
                key, _, value = s.partition(": ")
                try:
                    when = datetime.strptime(value, _TIME_FORMAT)
                except ValueError:
                    self.warn(n, line, "unrecognised time")
                    continue
                if key == "Last successful run":
                    job.last_successful_run = when
                else:
                    job.last_failed_run = when
        if "CONNECTIVITY" in job.required and job.network == "none":
            job.network = "unknown"
        return job

    def completed(self, block: list[tuple[int, str]]) -> CompletedJob | None:
        lineno, header = block[0]
        ago = parse_duration(_COMPLETED_HEADER.match(header)["ago"])  # type: ignore[index]
        for _, line in block[1:]:
            if m := _COMPLETED_JOB.match(line):
                pkg, _, worker = _target(m["target"])
                done = CompletedJob(ago=abs(ago) if ago else timedelta(0), label=m["label"],
                                    job_id=m["id"], package=pkg, worker=worker,
                                    line=lineno)  # fmt: skip
                for _, rest in block:
                    if src := _SOURCE_LINE.match(rest):
                        done.package = src["pkg"]
                return done
        self.warn(lineno, header, "completed job without a job line")
        return None


def parse_jobscheduler(text: str) -> tuple[JobSchedulerSnapshot, list[ParseWarning]]:
    parser = _Parser()
    snapshot = JobSchedulerSnapshot()
    sections = _sections(text)
    registered = next(
        (v for k, v in sections.items() if re.fullmatch(r"Registered \d+ jobs:", k)), None
    )
    if registered is None:
        parser.warnings.append(ParseWarning(source=SOURCE, message="no Registered jobs section"))
    else:
        for block in _blocks(registered, re.compile(r"^  JOB ")):
            if job := parser.job(block):
                snapshot.jobs.append(job)
    for block in _blocks(sections.get("Recently completed jobs:", []), _COMPLETED_HEADER):
        if done := parser.completed(block):
            snapshot.completed.append(done)
    return snapshot, parser.warnings
