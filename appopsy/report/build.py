"""Turn findings into the report's view model: grouping, ordering and plain labels.

Templates only lay this out. Everything a reader sees about a finding comes from
its rule spec (what it means, why it matters, what's probably benign, what to do)
and from the finding itself (summary, facts, evidence lines). Prose uses friendly
names (``appopsy.labels``); op constants and UID states appear only in tables.
"""

from __future__ import annotations

import functools
from collections import defaultdict
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime
from importlib import resources
from typing import Any

import yaml

from appopsy import __version__
from appopsy.labels import (
    ACCESS_CATEGORIES,
    CATEGORY,
    FRIENDLY,
    UNREPORTED_REQUIREMENTS,
    access_phrase,
    category_phrase,
    join,
    library_label,
    op_label,
    requirement_label,
    sample,
    short_class,
    state_label,
)
from appopsy.parsers.appops import UidRole
from appopsy.parsers.getprop import DeviceInfo
from appopsy.report import app_names
from appopsy.report.redaction import HIDDEN, HIDDEN_COLUMNS, Redaction
from appopsy.rules.case import CaseData
from appopsy.rules.engine import SEVERITIES, EvidenceRef, Finding, RuleSpec

INSTALLERS = {
    "com.android.vending": "Google Play",
    "com.google.android.packageinstaller": "a file opened on the phone (sideloaded)",
}
MAX_REFS_PER_FILE = 8
MAX_HEADLINE = 4
EMPTY = "—"
LOCATION_OPS = frozenset({"FINE_LOCATION", "COARSE_LOCATION"})
_SEVERITY_ORDER = {s: i for scale in SEVERITIES.values() for i, s in enumerate(reversed(scale))}


# --- app names -----------------------------------------------------------------


@functools.cache
def known_apps() -> dict[str, dict[str, Any]]:
    """The bundled map of well-known packages (``apps.yaml``)."""
    text = (resources.files("appopsy.report") / "apps.yaml").read_text(encoding="utf-8")
    data: dict[str, dict[str, Any]] = yaml.safe_load(text)
    return data


# The report being built (set by build_report): its redaction, if any; its collection
# time (redacted times are shown relative to it); job names several apps share.
_REDACTION: ContextVar[Redaction | None] = ContextVar("redaction", default=None)
_NOW: ContextVar[datetime | None] = ContextVar("now", default=None)
_SHARED: ContextVar[dict[str, set[str]]] = ContextVar("shared", default={})  # noqa: B039
JOBS_RULE = "unconstrained-background-work"


def _alias(package: str) -> str | None:
    redaction = _REDACTION.get()
    return redaction.aliases.get(package) if redaction else None


def _friendly(package: str) -> str | None:
    """apps.yaml first (curated), then the Wikidata names file; display only."""
    curated = known_apps().get(package, {}).get("name")
    return str(curated) if curated else app_names.names().get(package)


def app_name(package: str) -> str:
    """Friendly name, or the package name when the app isn't a well-known one."""
    if alias := _alias(package):
        return alias
    return _friendly(package) or package


def app_label(package: str, extra: str | None = None) -> str:
    """ "Facebook (com.facebook.katana)"; unknown apps by package alone."""
    if alias := _alias(package):
        return alias
    name = _friendly(package)
    inner = ", ".join(x for x in (package if name else None, extra) if x)
    shown = name or package
    return f"{shown} ({inner})" if inner else shown


def app_note(package: str, rule_id: str) -> str | None:
    note = known_apps().get(package, {}).get("notes", {}).get(rule_id)
    return str(note) if note else None


# --- views ---------------------------------------------------------------------


@dataclass
class Table:
    headers: list[str]
    rows: list[list[str]]


def table(headers: list[str], rows: list[list[str]]) -> Table | None:
    """Drop columns that are empty in every row; show the remaining gaps as a dash."""
    if not rows:
        return None
    keep = [i for i in range(len(headers)) if any(row[i] for row in rows)]
    return Table([headers[i] for i in keep], [[row[i] or EMPTY for i in keep] for row in rows])


@dataclass
class FindingView:
    finding: Finding
    app: str  # display label, e.g. "Android System Intelligence (com.google.android.as)"
    rest: str  # the summary after its leading package name, to follow the bold label
    tables: list[Table]
    evidence: list[str]  # one line per file: "dumpsys-appops.txt: lines 12, 40-42"
    note: str | None = None  # a known app's note for this rule
    more: str | None = None  # where the detail moved to, e.g. the appendix

    @property
    def anchor(self) -> str:
        """The finding's rule section, for links from the per-app list."""
        return f"rule-{self.finding.rule_id}-{self.finding.severity}"


@dataclass
class RuleGroup:
    spec: RuleSpec
    severity: str
    findings: list[FindingView]
    actions: list[str] = field(default_factory=list)  # app-specific "what you can do"
    compact: Table | None = None  # shown instead of each finding (details: appendix)
    compact_intro: str = ""
    appendix: str | None = None  # key of the appendix holding the detail

    @property
    def anchor(self) -> str:
        return f"rule-{self.spec.id}-{self.severity}"


@dataclass
class AppendixItem:
    heading: str  # an app label, or "" for an untitled table
    text: str = ""  # device-derived prose (escaped by the template)
    tables: list[Table] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


@dataclass
class Appendix:
    key: str  # anchor: "appendix-<key>"
    title: str
    intro: str
    items: list[AppendixItem]


@dataclass
class AppView:
    package: str
    label: str
    origin: str  # "Google Play", "came with the phone", ...
    findings: list[FindingView]


@dataclass
class PackView:
    pack: str
    severities: list[str]  # most severe first
    counts: dict[str, int]  # severity -> findings in the main section
    by_severity: list[tuple[str, list[RuleGroup]]]
    system: list[RuleGroup]
    rules: list[RuleSpec]
    system_table: Table | None = None  # one row per platform component (details: appendix)
    system_notes: list[tuple[str, str]] = field(default_factory=list)  # (component, note)


@dataclass
class Report:
    device: DeviceInfo
    collected: datetime | None  # device local time
    collected_label: str  # "2030-01-01 00:00", or a redacted copy's stand-in
    version: str
    headline: list[str]
    packs: list[PackView]
    apps: list[AppView]
    remediation: list[RuleGroup]
    warnings: int
    rules_run: list[RuleSpec] = field(default_factory=list)
    redacted: int | None = None  # number of apps shown under an alias; None: not redacted
    appendix: list[Appendix] = field(default_factory=list)


def evidence_lines(refs: list[EvidenceRef]) -> list[str]:
    by_file: dict[str, set[tuple[int, int]]] = defaultdict(set)
    for ref in refs:
        by_file[ref.file].add((ref.start, ref.end))
    out = []
    for file in sorted(by_file):
        spans = sorted(by_file[file])
        shown = [str(a) if a == b else f"{a}-{b}" for a, b in spans[:MAX_REFS_PER_FILE]]
        more = len(spans) - len(shown)
        word = "line" if len(spans) == 1 and spans[0][0] == spans[0][1] else "lines"
        out.append(f"{file}: {word} {', '.join(shown)}" + (f" and {more} more" if more else ""))
    return out


def origin(case: CaseData, package: str) -> str:
    match case.classify(package):
        case "user_installed":
            installer = case.installers.get(package)
            if installer is None:
                return "installer not recorded"
            if installer in INSTALLERS:
                return INSTALLERS[installer]
            return "another app store" if _alias(installer) else app_name(installer)
        case "preinstalled":
            return "came with the phone"
        case "system":
            return "part of Android"
    return "unknown"


def _label(case: CaseData, f: Finding) -> str:
    package = f.package or "(no app)"
    uid = f.facts.get("uid")
    link = case.uid_links.get((uid, package)) if isinstance(uid, int) else None
    if link is not None and link.role is UidRole.SECONDARY:
        return app_label(package, f"secondary UID {uid}")
    return app_label(package)


def _time(value: str) -> str:
    """Whole seconds ("2030-01-01 00:00:00"); in a redacted copy, the day relative to
    collection ("today", "yesterday", "3 days ago"): exact times show when you used
    an app."""
    now = _NOW.get()
    if _REDACTION.get() is None or now is None:
        return value[:19]
    try:
        days = (now.date() - datetime.fromisoformat(value[:10]).date()).days
    except ValueError:
        return "some time ago"
    if days <= 0:
        return "today"
    return "yesterday" if days == 1 else f"{days} days ago"


def _job_rows(f: Finding) -> list[list[str]]:
    """One row per distinct job; repeats merge with a count, and a job name several
    apps share is labelled with its library."""
    shared = _SHARED.get()
    rows: dict[tuple[str, str, str], int] = {}
    for j in f.facts.get("jobs", []):
        name = short_class(str(j["what"]))
        label = f"{library_label(name)}: {name}" if name in shared else name
        requires = ", ".join(
            requirement_label(r) for r in j["requires"] if r not in UNREPORTED_REQUIREMENTS
        )
        key = (label, requires, j["periodic"] or "")
        rows[key] = rows.get(key, 0) + 1
    return [[label, str(n) if n > 1 else "", req, per] for (label, req, per), n in rows.items()]


def _tables(f: Finding) -> list[Table]:
    facts: dict[str, Any] = f.facts
    tables: list[Table | None] = []
    match f.rule_id:
        case "chatty-wakeups":
            rows = [[a["tag"], str(a["wakeups"])] for a in facts.get("top_alarms", [])]
            tables.append(table(["Alarm", "Wake-ups"], rows))
        case "unconstrained-background-work":
            headers = ["Job", "Count", "Waits only for", "Repeats every"]
            tables.append(table(headers, _job_rows(f)))
        case "background-sensor-attempt":
            rows = [
                [
                    op_label(a["op"]),
                    "only while in use" if a["mode"] == "foreground" else "not allowed",
                    ", ".join(state_label(s) for s in a["rejected_in"]),
                    _time(a["last_reject"]),
                ]
                for a in facts.get("attempts", [])
            ]
            tables.append(table(["Sensor", "Setting", "Refused while", "Last refused"], rows))
        case "sensor-use-summary":
            access, location = [], []
            for u in facts.get("uses", []):
                if "state" in u:
                    access.append([op_label(u["op"]), state_label(u["state"]), _time(u["time"]),
                                   u["duration"] or ""])  # fmt: skip
                else:
                    location.append([u.get("provider", u["op"]), u["total"], u["background"],
                                     str(u["locations"])])  # fmt: skip
            hidden = [[r["provider"], r["tag"] or ""] for r in facts.get("requests", [])]
            tables.append(table(["Sensor", "App was", "Last used", "For"], access))
            headers = ["Location provider", "Requested for", "In background",
                       "Location fixes delivered"]  # fmt: skip
            tables.append(table(headers, location))
            tables.append(table(["Provider", "Requested as"], hidden))
        case "over-privileged-app":
            allowed: dict[str, str] = facts.get("allowed", {})
            rows = []
            for cat in ACCESS_CATEGORIES:
                if (c := facts.get("categories", {}).get(cat.key)) is None:
                    continue
                ops = ", ".join(op for op in cat.ops if op in allowed)
                detail = cat.full_detail if c["scope"] == "full" else cat.partial_detail
                when = "at any time" if c["mode"] == "allow" else "only while in use"
                rows.append([f"{cat.name} ({ops})", when, detail])
            tables.append(table(["Allowed", "When", "Scope"], rows))
        case "background-sensor-use":
            rows = [
                [
                    op_label(u["op"]),
                    "at any time" if u["mode"] == "allow" else "only while in use",
                    ", ".join(state_label(st) for st in u["states"]),
                    _time(u["last"]),
                ]
                for u in facts.get("uses", [])
            ]
            tables.append(table(["Sensor", "Setting", "Used while", "Last used"], rows))
    return [t for t in tables if t is not None]


def _redacted_rest(f: Finding, rest: str) -> str:
    """A private app's summary without the names inside it (jobs list them)."""
    if f.rule_id == "unconstrained-background-work":
        n = len(f.facts["jobs"])
        return (
            f" has {n} background {'job' if n == 1 else 'jobs'} that can run without "
            "charging, the phone being idle or Wi-Fi (names hidden)."
        )
    return rest


def _hide(tables: list[Table]) -> list[Table]:
    out = []
    for t in tables:
        cols = {i for i, h in enumerate(t.headers) if h in HIDDEN_COLUMNS}
        rows = [[HIDDEN if i in cols else c for i, c in enumerate(row)] for row in t.rows]
        out.append(Table(t.headers, rows))
    return out


def _view(case: CaseData, f: Finding) -> FindingView:
    # "<pkg> tried to ..." follows the bold app label; any other summary gets a colon.
    leads = bool(f.package) and f.summary.startswith(f"{f.package} ")
    rest = f.summary[len(f.package or "") :] if leads else f": {f.summary}"
    note = app_note(f.package, f.rule_id) if f.package else None
    tables = _tables(f)
    if f.package and _alias(f.package):
        rest, tables = _redacted_rest(f, rest), _hide(tables)
    return FindingView(f, _label(case, f), rest, tables, evidence_lines(f.evidence), note)


def _sort_key(f: Finding) -> tuple[int, str]:
    # A ranking keeps its rank order; everything else is by app name.
    rank = f.facts.get("rank")
    return (rank if isinstance(rank, int) else 0, f.package or "")


# --- prose built from several findings: headline and app-specific actions --------


def _any_time(f: Finding) -> list[tuple[str, str]]:
    """(category, scope) an app may use at any time: data and sensors, not running in
    the background, and not selected photos only (the privacy-friendly choice)."""
    cats: dict[str, dict[str, str]] = f.facts.get("categories", {})
    return [
        (key, c["scope"])
        for key, c in cats.items()
        if c["mode"] == "allow" and key != "background" and (key, c["scope"]) not in FRIENDLY
    ]


def _core(package: str | None) -> set[str]:
    """Kinds of access the app's main job needs (``core`` in apps.yaml)."""
    return set(known_apps().get(package or "", {}).get("core", []))


def _category_of(op: str) -> str | None:
    return next((c.key for c in ACCESS_CATEGORIES if op in c.ops), None)


# Headline: one sentence per kind of finding, most severe first. A kind is a rule,
# and for the sensor rules also the sensor (and for camera and microphone, whether
# the use was visible): different sensors are never merged into one clause, so a
# sentence can't suggest that apps used a sensor only one of them did.
SENSOR_KINDS = (  # (key, ops, phrase), in headline order
    ("microphone", frozenset({"RECORD_AUDIO"}), "the microphone"),
    ("camera", frozenset({"CAMERA"}), "the camera"),
    ("location", LOCATION_OPS, "your location"),
    ("body_sensors", frozenset({"BODY_SENSORS"}), "body sensors"),
)
RULE_ORDER = (
    "background-sensor-use",
    "background-sensor-attempt",
    "chatty-wakeups",
    "unconstrained-background-work",
    "over-privileged-app",
)
MAX_NAMED = 3


@dataclass
class _Line:
    severity: str
    order: tuple[int, int, int]  # rule, sensor, variant
    text: str


def _apps(names: list[str]) -> tuple[str, bool]:
    """ "A, B, C and 5 more" (at most three named) and whether it's plural."""
    names = sorted(names, key=str.lower)
    return sample(names, MAX_NAMED), len(names) > 1


def _by_sensor(
    fs: list[Finding], ops_of: Callable[[Finding], set[str]]
) -> list[tuple[int, str, list[Finding]]]:
    """(sensor index, phrase, findings) for each sensor kind some finding involves."""
    out = []
    for i, (_, ops, phrase) in enumerate(SENSOR_KINDS):
        group = [f for f in fs if ops_of(f) & ops]
        if group:
            out.append((i, phrase, group))
    return out


def _headline_background_use(fs: list[Finding], case: CaseData) -> list[_Line]:
    rule = RULE_ORDER.index("background-sensor-use")
    lines = []

    def uses(f: Finding, ops: frozenset[str]) -> list[dict[str, Any]]:
        return [u for u in f.facts["uses"] if u["op"] in ops]

    for i, (key, ops, phrase) in enumerate(SENSOR_KINDS):
        group = [f for f in fs if uses(f, ops)]
        if not group:
            continue
        if key in ("microphone", "camera"):
            hidden = [
                f for f in group if any(set(u["states"]) & {"bg", "cch"} for u in uses(f, ops))
            ]
            visible = [f for f in group if f not in hidden]
            if hidden:
                apps, _ = _apps([app_name(f.package or "") for f in hidden])
                lines.append(_Line(
                    "concern", (rule, i, 0),
                    f"{apps} used {phrase} in the background, where nothing on screen shows it.",
                ))  # fmt: skip
            if visible:
                apps, _ = _apps([app_name(f.package or "") for f in visible])
                lines.append(_Line(
                    "notable", (rule, i, 1),
                    f"{apps} used {phrase} from a foreground service, which shows a "
                    "notification while it runs.",
                ))  # fmt: skip
        else:
            apps, _ = _apps([app_name(f.package or "") for f in group])
            received = "body-sensor data" if key == "body_sensors" else phrase
            lines.append(_Line(
                "notable", (rule, i, 0), f"{apps} received {received} while not on screen."
            ))  # fmt: skip
    return lines


def _headline_attempts(fs: list[Finding], case: CaseData) -> list[_Line]:
    rule = RULE_ORDER.index("background-sensor-attempt")
    lines = []
    for i, phrase, group in _by_sensor(fs, lambda f: {a["op"] for a in f.facts["attempts"]}):
        ops = SENSOR_KINDS[i][1]
        attempts = [a for f in group for a in f.facts["attempts"] if a["op"] in ops]
        apps, plural = _apps([app_name(f.package or "") for f in group])
        why = (
            "your settings allow it only while the app is in use"
            if all(a["mode"] == "foreground" for a in attempts)
            else "your settings don't allow it"
        )
        verb = "were" if plural else "was"
        lines.append(_Line(
            group[0].severity, (rule, i, 0),
            f"{apps} tried to use {phrase} in the background and {verb} refused, because {why}.",
        ))  # fmt: skip
    return lines


def _headline_wakeups(fs: list[Finding], case: CaseData) -> list[_Line]:
    apps, _ = _apps([app_name(f.package or "") for f in fs])
    limit = fs[0].facts["threshold"]
    return [_Line(
        fs[0].severity, (RULE_ORDER.index("chatty-wakeups"), 0, 0),
        f"{apps} woke the phone more than {limit:g} times an hour on average.",
    )]  # fmt: skip


def _headline_jobs(fs: list[Finding], case: CaseData) -> list[_Line]:
    # Apps that came with the phone are info here: not headline material.
    fs = sorted((f for f in fs if f.severity != "info"), key=lambda f: -len(f.facts["jobs"]))
    if not fs:
        return []
    counts = [(app_name(f.package or ""), len(f.facts["jobs"])) for f in fs]
    total = sum(n for _, n in counts)
    order = (RULE_ORDER.index("unconstrained-background-work"), 0, 0)
    if len(counts) == 1:
        name, n = counts[0]
        jobs = "job" if n == 1 else "jobs"
        return [_Line(fs[0].severity, order, f"{name} has {n} background {jobs} that can run on "
                      "battery and mobile data at any time.")]  # fmt: skip
    named = [f"{name} ({n})" for name, n in counts[:MAX_NAMED]]
    more = len(counts) - len(named)
    listed = f"{', '.join(named)} and {more} more apps" if more else join(named)
    return [_Line(fs[0].severity, order, f"{listed} have background jobs that can run on "
                  f"battery and mobile data at any time, {total} in all.")]  # fmt: skip


def _headline_access(fs: list[Finding], case: CaseData) -> list[_Line]:
    """The widest-access app, and the widest of the other kind (installed or came with
    the phone), so access a preinstalled app has isn't hidden behind installed ones."""
    ranked = sorted((f for f in fs if f.facts["count"]), key=lambda f: f.facts["rank"])
    if not ranked:
        return []
    rule = RULE_ORDER.index("over-privileged-app")
    top = ranked[0]
    top_kind = case.classify(top.package or "")
    name = app_name(top.package or "")
    if top_kind == "preinstalled":
        name += ", which came with the phone,"
    sentence = (
        f"{name} has the broadest access: {top.facts['count']} of the "
        f"{top.facts['checked']} kinds of sensitive access appopsy checks"
    )
    any_time = _any_time(top)
    text = sentence + (f", including {category_phrase(any_time)} at any time." if any_time else ".")
    out = [_Line(top.severity, (rule, 0, 0), text)]
    others = [f for f in ranked[1:] if case.classify(f.package or "") != top_kind and _any_time(f)]
    if others:
        other = others[0]
        if top_kind == "preinstalled":
            lead = f"Of the apps you installed, {app_name(other.package or '')}"
        else:
            lead = f"{app_name(other.package or '')}, which came with the phone,"
        text = f"{lead} can use {category_phrase(_any_time(other))} at any time."
        out.append(_Line(other.severity, (rule, 0, 1), text))
    return out


HEADLINES: dict[str, Callable[[list[Finding], CaseData], list[_Line]]] = {
    "background-sensor-use": _headline_background_use,
    "background-sensor-attempt": _headline_attempts,
    "chatty-wakeups": _headline_wakeups,
    "unconstrained-background-work": _headline_jobs,
    "over-privileged-app": _headline_access,
}


def headline(case: CaseData, main: list[Finding]) -> list[str]:
    """Up to MAX_HEADLINE sentences, one per kind of finding, concern first."""
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for f in main:
        by_rule[f.rule_id].append(f)
    lines = [line for r, fs in by_rule.items() if r in HEADLINES for line in HEADLINES[r](fs, case)]
    lines.sort(key=lambda line: (_SEVERITY_ORDER[line.severity], line.order))
    if not lines:
        return ["Nothing stood out about the apps on this phone."]
    return [line.text for line in lines[:MAX_HEADLINE]]


# Permission names as Settings shows them, and the step that narrows each one.
PERMISSION = {
    "location": "Location", "camera": "Camera", "microphone": "Microphone",
    "contacts": "Contacts", "call_log": "Call logs", "sms": "SMS",
    "photos_videos": "Photos and videos", "body_sensors": "Body sensors",
}  # fmt: skip
NARROW = {
    "location": "\u201cAllow only while using the app\u201d",
    "camera": "\u201cAsk every time\u201d",
    "microphone": "\u201cAsk every time\u201d",
    "photos_videos": "\u201cAllow limited access\u201d",
}


def _narrow_step(key: str) -> str:
    choice = NARROW.get(key, "\u201cDon't allow\u201d if it doesn't need them")
    return f"{PERMISSION[key]} to {choice}"


def _action(f: Finding) -> str | None:
    """One concrete step for this app, or None: no line without a step to take, and
    none for access the app's main job needs."""
    name = app_name(f.package or "")
    settings = f"Settings > Apps > {name}"
    core = _core(f.package)
    match f.rule_id:
        case "unconstrained-background-work":
            return None  # one line for all of them: see _jobs_action
        case "chatty-wakeups":
            return (
                f"{name}: {settings} > App battery usage: choose Restricted to limit how "
                "often it can wake the phone."
            )
        case "background-sensor-attempt":
            keys = sorted({k for a in f.facts["attempts"] if (k := _category_of(a["op"]))})
            perms = join([PERMISSION[k] for k in keys])
            return (
                f"{name}: {settings} > Permissions > {perms}: choose \u201cDon't allow\u201d if "
                "you don't use the features that need it."
            )
        case "over-privileged-app":
            steps = [_narrow_step(k) for k, _ in _any_time(f) if k not in core]
            if not steps:
                return None
            return f"{name}: {settings} > Permissions: set {'; set '.join(steps)}."
        case "background-sensor-use":
            used_keys = {
                k for u in f.facts["uses"]
                if u["mode"] == "allow" or u["op"] in ("CAMERA", "RECORD_AUDIO")
                if (k := _category_of(u["op"])) and k not in core
            }  # fmt: skip
            steps = [_narrow_step(k) for k in PERMISSION if k in used_keys]
            if not steps:
                return None
            return (
                f"{name}: {settings} > Permissions: set {'; set '.join(steps)}. Use from a "
                "foreground service you start (such as navigation) keeps working."
                if used_keys == {"location"}
                else f"{name}: {settings} > Permissions: set {'; set '.join(steps)}."
            )
    return None


def _compact_jobs(fs: list[Finding]) -> Table | None:
    """Apps that came with the phone: one row per app (details in the appendix)."""
    shared = _SHARED.get()
    rows = []
    for f in sorted(fs, key=lambda f: (-len(f.facts["jobs"]), app_name(f.package or ""))):
        jobs = [short_class(str(j["what"])) for j in f.facts["jobs"]]
        n_shared = sum(name in shared for name in jobs)
        rows.append([app_label(f.package or ""), str(len(jobs)), str(n_shared) if n_shared else ""])
    return table(["App", "Jobs", "From shared libraries"], rows)


def _jobs_action(fs: list[Finding]) -> str | None:
    """One line for every installed app with background work (not the ones that came
    with the phone): the same step, with each app's job count."""
    mine = sorted((f for f in fs if f.severity != "info"), key=lambda f: -len(f.facts["jobs"]))
    if not mine:
        return None
    apps = ", ".join(f"{app_name(f.package or '')} ({len(f.facts['jobs'])})" for f in mine)
    return (
        "Settings > Apps > (the app) > App battery usage: choose Restricted to defer its "
        f"background jobs. Apps and their jobs: {apps}."
    )


def _compact_installed_jobs(fs: list[Finding]) -> Table | None:
    """Installed apps' background work as one table: job count and a few names."""
    rows = []
    for f in sorted(fs, key=lambda f: (-len(f.facts["jobs"]), app_name(f.package or ""))):
        names = list(dict.fromkeys(short_class(str(j["what"])) for j in f.facts["jobs"]))
        hidden = bool(f.package and _alias(f.package))
        examples = HIDDEN if hidden else ", ".join(names[:3]) + (", ..." if len(names) > 3 else "")
        rows.append([app_label(f.package or ""), str(len(f.facts["jobs"])), examples])
    return table(["App", "Jobs", "Includes"], rows)


def _system_summary(groups: list[RuleGroup]) -> tuple[Table | None, list[tuple[str, str]]]:
    """Platform components as one table, a row per finding (how many components, the
    first few by name), plus the notes that explain a component's findings."""
    rows, notes = [], {}
    for g in groups:
        names = list(dict.fromkeys(v.app for v in g.findings))
        rows.append([g.spec.title, f"{len(names)}: {sample(names, 4)}"])
        notes.update({v.app: v.note for v in g.findings if v.note})
    return table(["Finding", "Components"], rows), sorted(notes.items())


ACCESS_RULE = "over-privileged-app"
SENSOR_SUMMARY_RULE = "sensor-use-summary"


def _compact_access(fs: list[Finding]) -> Table | None:
    """The access ranking as one table: kinds of access and how many at any time."""
    rows = []
    for f in sorted(fs, key=lambda f: f.facts["rank"]):
        cats = f.facts.get("categories", {})
        counted = [CATEGORY[k].name.lower() for k in cats if (k, cats[k]["scope"]) not in FRIENDLY]
        kinds = f"{len(counted)}: {', '.join(counted)}" if counted else "none"
        rows.append(
            [app_label(f.package or ""), kinds, str(len(_any_time(f))) if _any_time(f) else ""]
        )
    return table(["App", "Kinds of access", "At any time"], rows)


def _compact_sensor_use(fs: list[Finding]) -> Table | None:
    """Recent sensor use as one table: what each app used, when last, and its longest
    location request."""
    rows = []
    for f in sorted(fs, key=lambda f: app_name(f.package or "").lower()):
        uses = f.facts.get("uses", [])
        used = access_phrase(u["op"] for u in uses if "state" in u)
        times = [u["time"] for u in uses if "time" in u]
        held = max((u["total"] for u in uses if "total" in u), default="", key=_duration_key)
        rows.append([app_label(f.package or ""), used or "location updates only",
                     _time(max(times)) if times else "", held])  # fmt: skip
    return table(["App", "Used", "Last used", "Longest location request"], rows)


def _duration_key(value: str) -> tuple[int, str]:
    """Sort "4 days, 0:00:03" after "23:59:59" (str(timedelta) forms)."""
    days = int(value.split(" day")[0]) if " day" in value else 0
    return (days, value.split(", ")[-1].rjust(8, "0"))


def _groups(
    case: CaseData, specs: dict[str, RuleSpec], findings: list[Finding], compact: bool = False
) -> list[RuleGroup]:
    """``compact`` (the main findings): long groups become one table, with the detail
    in an appendix: the access ranking, recent sensor use, and the background work
    of apps that came with the phone; installed apps' job lists move there too."""
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_rule[f.rule_id].append(f)
    groups = []
    for rule, fs in sorted(by_rule.items()):
        fs = sorted(fs, key=_sort_key)
        actions = [a for f in fs if (a := _action(f))]
        if rule == JOBS_RULE and (line := _jobs_action(fs)):
            actions.insert(0, line)
        group = RuleGroup(specs[rule], fs[0].severity, [_view(case, f) for f in fs], actions)
        if compact and rule == JOBS_RULE and group.severity == "info":
            group.compact, group.appendix = _compact_jobs(fs), "jobs"
            group.compact_intro = (
                "These apps came with the phone; most of their jobs come from shared Google "
                "libraries."
            )
        elif compact and rule == JOBS_RULE:
            group.compact, group.appendix = _compact_installed_jobs(fs), "jobs"
            group.compact_intro = "One row per app, with up to three of its jobs."
        elif compact and rule == ACCESS_RULE:
            group.compact, group.appendix = _compact_access(fs), "access"
            group.compact_intro = (
                "Ranked by kinds of access, then how many at any time. Each app allowed "
                "something at any time has a full entry."
            )
        elif compact and rule == SENSOR_SUMMARY_RULE:
            group.compact, group.appendix = _compact_sensor_use(fs), "sensors"
            group.compact_intro = "One row per app; each use, by sensor and state, is listed."
        groups.append(group)
    return sorted(groups, key=lambda g: _SEVERITY_ORDER[g.severity])


def _app_order(package: str, fs: list[Finding]) -> tuple[int, int, str]:
    """Most severe finding first, then the number of findings, then name."""
    return (min(_SEVERITY_ORDER[f.severity] for f in fs), -len(fs), app_name(package).lower())


def build_report(
    case: CaseData,
    specs: list[RuleSpec],
    findings: list[Finding],
    packs: tuple[str, ...] = ("privacy",),
    redaction: Redaction | None = None,
) -> Report:
    """``packs``: the packs asked for; each gets a section, even with no rules yet.
    ``redaction``: show private apps under aliases (see ``appopsy.report.redaction``)."""
    tokens = (
        _REDACTION.set(redaction),
        _NOW.set(case.clock.local if case.clock else None),
        _SHARED.set(shared_jobs(findings)),
    )
    try:
        report = _build(case, specs, findings, packs)
    finally:
        _SHARED.reset(tokens[2])
        _NOW.reset(tokens[1])
        _REDACTION.reset(tokens[0])
    if redaction is not None:
        report.redacted = len({f.package for f in findings if redaction.is_private(f.package)})
    return report


def _collected_label(case: CaseData) -> str:
    if _REDACTION.get() is not None:
        return "on a date not shown in this copy"
    if case.clock is None or case.clock.local is None:
        return "at an unknown time"
    return case.clock.local.strftime("%Y-%m-%d %H:%M") + " by the phone's clock"


def shared_jobs(findings: list[Finding]) -> dict[str, set[str]]:
    """Job name -> packages, for names that two or more apps schedule (libraries)."""
    by_name: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        if f.rule_id == JOBS_RULE and f.package:
            for j in f.facts["jobs"]:
                by_name[short_class(str(j["what"]))].add(f.package)
    return {name: pks for name, pks in by_name.items() if len(pks) >= 2}


def _appendix(case: CaseData, main: list[Finding], findings_all: list[Finding]) -> list[Appendix]:
    shared = _SHARED.get()
    redaction = _REDACTION.get()
    out = []
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for f in main:
        by_rule[f.rule_id].append(f)

    access = [_view(case, f) for f in sorted(by_rule[ACCESS_RULE], key=_sort_key) if _any_time(f)]
    if access:
        out.append(Appendix(
            "access", "Sensitive access at any time",
            "Every app allowed at least one kind of sensitive access at any time, in rank order.",
            [AppendixItem(v.app, v.rest.lstrip(": "), v.tables) for v in access],
        ))  # fmt: skip

    sensors = sorted(by_rule[SENSOR_SUMMARY_RULE], key=lambda f: app_name(f.package or "").lower())
    if sensors:
        out.append(Appendix(
            "sensors", "Recent sensor use",
            "Each app's recorded uses, by sensor and the state the app was in.",
            [AppendixItem(v.app, "", v.tables) for v in map(lambda f: _view(case, f), sensors)],
        ))  # fmt: skip

    items = []
    if shared:
        rows = []
        for name, pks in sorted(shared.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            hidden = redaction is not None and name in redaction.hidden
            apps = sorted(app_name(p) for p in pks)
            rows.append([library_label(name), HIDDEN if hidden else name, str(len(pks)),
                         ", ".join(apps)])  # fmt: skip
        if t := table(["Library", "Job", "Apps", "Used by"], rows):
            items.append(AppendixItem(
                "Shared job libraries",
                "Job names that several apps schedule because they come from the same "
                "library. Each is listed once here; the apps' tables label them with it.",
                [t],
            ))  # fmt: skip

    def job_order(f: Finding) -> tuple[int, str]:
        return (_SEVERITY_ORDER[f.severity], app_name(f.package or "").lower())

    jobs = sorted(by_rule[JOBS_RULE], key=job_order)
    items += [
        AppendixItem(v.app, v.rest.lstrip(": "), v.tables, v.evidence)
        for v in (_view(case, f) for f in jobs)
    ]
    if items:
        out.append(Appendix(
            "jobs", "Background jobs",
            "The full job lists behind the background-work findings.",
            items,
        ))  # fmt: skip
    system = sorted(
        (f for f in findings_all if f.section == "system"),
        key=lambda f: (app_name(f.package or "").lower(), f.rule_id),
    )
    if system:
        views = [_view(case, f) for f in system]
        items = [
            AppendixItem(f"{v.app}: {v.finding.title}", v.rest.lstrip(": "), v.tables, v.evidence)
            for v in views
        ]
        intro = "Every finding about platform components, at the lowest level of its scale."
        out.append(Appendix("system", "System components", intro, items))
    return out


def _build(
    case: CaseData, specs: list[RuleSpec], findings: list[Finding], packs: tuple[str, ...]
) -> Report:
    by_id = {s.id: s for s in specs}
    pack_views = []
    for pack in packs:
        scale = list(reversed(SEVERITIES[pack]))  # most severe first
        mine = [f for f in findings if f.pack == pack]
        main = [f for f in mine if f.section == "main"]
        pack_views.append(
            PackView(
                pack=pack,
                severities=scale,
                counts={s: sum(f.severity == s for f in main) for s in scale},
                by_severity=[
                    (s, _groups(case, by_id, [f for f in main if f.severity == s], compact=True))
                    for s in scale
                    if any(f.severity == s for f in main)
                ],
                system=_groups(case, by_id, [f for f in mine if f.section == "system"]),
                rules=[s for s in specs if s.pack == pack],
            )
        )
        pack_views[-1].system_table, pack_views[-1].system_notes = _system_summary(
            pack_views[-1].system
        )
    main = [f for f in findings if f.section == "main"]
    apps: dict[str, list[Finding]] = defaultdict(list)
    for f in main:
        if f.package:
            apps[f.package].append(f)
    app_views = [
        AppView(
            package,
            app_label(package),
            origin(case, package),
            [
                _view(case, f)
                for f in sorted(fs, key=lambda f: (_SEVERITY_ORDER[f.severity], f.rule_id))
            ],
        )
        for package, fs in sorted(apps.items(), key=lambda kv: _app_order(kv[0], kv[1]))
    ]
    return Report(
        device=case.device,
        collected=case.clock.local if case.clock else None,
        collected_label=_collected_label(case),
        version=__version__,
        headline=headline(case, main),
        packs=pack_views,
        apps=app_views,
        # An app allowed nothing sensitive has nothing to narrow.
        remediation=_groups(case, by_id, [f for f in main if f.facts.get("allowed") != {}]),
        warnings=len(case.warnings),
        rules_run=specs,
        appendix=_appendix(case, main, findings),
    )
