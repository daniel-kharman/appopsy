"""Privacy-pack rule functions. Each is referenced by id from specs/privacy/*.yaml."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from appopsy.collectors.alarm import FILENAME as ALARM_FILE
from appopsy.collectors.appops import FILENAME as APPOPS_FILE
from appopsy.collectors.jobscheduler import FILENAME as JOBSCHEDULER_FILE
from appopsy.collectors.location import FILENAME as LOCATION_FILE
from appopsy.labels import (
    ACCESS_CATEGORIES,
    FRIENDLY,
    access_phrase,
    category_phrase,
    join,
    sample,
    short_class,
)
from appopsy.parsers.appops import OpCategory, OpEvent, PackageOp, UidOps
from appopsy.rules.case import CaseData
from appopsy.rules.engine import EvidenceRef, Finding, RuleSpec, make_finding, rule_function

# Ops for sensors and location deliveries. MONITOR_* (location requests) and GPS
# are deliberately absent: they don't show that a sensor delivered anything.
SENSOR_OPS = ("FINE_LOCATION", "COARSE_LOCATION", "CAMERA", "RECORD_AUDIO", "BODY_SENSORS")


def _fmt(td: Any) -> str:
    return str(td).split(".")[0]


@rule_function("chatty-wakeups", thresholds=("wakeups_per_hour",))
def chatty_wakeups(case: CaseData, spec: RuleSpec) -> list[Finding]:
    alarms = case.alarms
    if not alarms.runtime_elapsed:
        return []
    hours = alarms.runtime_elapsed.total_seconds() / 3600
    limit = spec.threshold("wakeups_per_hour")
    findings = []
    for stats in alarms.stats:
        # `wakeups` counts only wakeup alarms (RTC_WAKEUP, ELAPSED_REALTIME_WAKEUP);
        # the per-tag `alarms` counts include non-waking ones and are not used.
        rate = stats.wakeups / hours
        if rate <= limit:
            continue
        tags = sorted(stats.tags, key=lambda t: t.wakeups, reverse=True)
        findings.append(
            make_finding(
                spec,
                case,
                stats.package,
                f"{stats.package} woke the phone {stats.wakeups} times in {hours:.1f} hours, "
                f"{rate:.1f} times an hour on average (the threshold is {limit:g}).",
                facts={
                    "wakeups": stats.wakeups,
                    "hours": round(hours, 2),
                    "per_hour": round(rate, 2),
                    "threshold": limit,
                    "top_alarms": [{"tag": t.tag, "wakeups": t.wakeups} for t in tags[:5]],
                },
                evidence=case.evidence(ALARM_FILE, stats.line, stats.end_line),
            )
        )
    return findings


@rule_function("unconstrained-background-work")
def unconstrained_background_work(case: CaseData, spec: RuleSpec) -> list[Finding]:
    by_package: dict[str, list[Any]] = defaultdict(list)
    undetermined: dict[str, int] = defaultdict(int)
    for job in case.jobs.jobs:
        if job.is_unconstrained is True:
            by_package[job.package].append(job)
        elif job.is_unconstrained is None:
            undetermined[job.package] += 1
    findings = []
    for package, jobs in sorted(by_package.items()):
        listed = [
            {
                "what": j.worker or j.service,
                "workmanager": j.is_workmanager,
                "requires": j.requirements,
                "periodic": _fmt(j.periodic_interval) if j.periodic_interval else None,
            }
            for j in jobs
        ]
        # Repeated names (a library's worker scheduled several times) are listed once,
        # with a count: "GnpWorker (4)".
        counts = Counter(short_class(str(item["what"])) for item in listed)
        names = [f"{n} ({k})" if k > 1 else n for n, k in counts.items()]
        jobs_word = "job" if len(jobs) == 1 else "jobs"
        summary = (
            f"{package} has {len(jobs)} background {jobs_word} that can run without "
            "charging, the phone being idle or Wi-Fi"
            + (f": {join(names)}." if len(names) <= 3 else f", including {sample(names)}.")
        )
        if undetermined[package]:
            summary += (
                f" {undetermined[package]} more need a network, but this capture doesn't say "
                "which kind."
            )
        evidence = [
            ref for j in jobs for ref in case.evidence(JOBSCHEDULER_FILE, j.line, j.end_line)
        ]
        findings.append(
            make_finding(
                spec,
                case,
                package,
                summary,
                facts={"jobs": listed, "undetermined": undetermined[package]},
                evidence=evidence,
                # Apps that came with the phone: info (their jobs are mostly shared
                # Google libraries); the report lists them compactly.
                severity="info" if case.classify(package) == "preinstalled" else None,
            )
        )
    return findings


def _sensor_ops(uid: UidOps) -> list[tuple[str, PackageOp]]:
    return [
        (pkg.name, op)
        for pkg in uid.packages
        for op in pkg.ops
        if op.op in SENSOR_OPS and op.category in (OpCategory.LOCATION_DELIVERY, OpCategory.OTHER)
    ]


@rule_function("background-sensor-attempt")
def background_sensor_attempt(case: CaseData, spec: RuleSpec) -> list[Finding]:
    findings = []
    for uid in case.appops.uids:
        per_package: dict[str, list[tuple[PackageOp, str, list[OpEvent]]]] = defaultdict(list)
        for package, op in _sensor_ops(uid):
            mode = uid.effective_mode(op)
            if mode not in ("foreground", "ignore"):
                continue
            rejects = [e for e in op.events if e.kind == "reject" and e.in_background]
            if rejects:
                per_package[package].append((op, mode, rejects))
        for package, items in per_package.items():
            evidence: list[EvidenceRef] = []
            attempts: list[dict[str, Any]] = []
            for op, mode, rejects in items:
                key = op.switch_op or op.op
                evidence += case.evidence(APPOPS_FILE, uid.mode_lines.get(key))
                evidence += [r for e in rejects for r in case.evidence(APPOPS_FILE, e.line)]
                attempts.append(
                    {
                        "op": op.op,
                        "mode": mode,
                        "rejected_in": sorted({e.uid_state for e in rejects}),
                        "last_reject": max(e.time for e in rejects).isoformat(sep=" "),
                    }
                )
            attempts.sort(key=lambda a: SENSOR_OPS.index(a["op"]))
            ops = access_phrase(a["op"] for a in attempts)
            findings.append(
                make_finding(
                    spec,
                    case,
                    package,
                    f"{package} tried to use {ops} in the background, where it isn't allowed, "
                    "and was refused.",
                    facts={"uid": uid.uid, "attempts": attempts},
                    evidence=evidence,
                )
            )
    return findings


# Not on screen: background, cached, or a foreground service (CLAUDE.md, UID states).
OFF_SCREEN_STATES = ("bg", "cch", "fgsvc")
CONCERN_OPS = frozenset({"CAMERA", "RECORD_AUDIO"})


@rule_function("background-sensor-use")
def background_sensor_use(case: CaseData, spec: RuleSpec) -> list[Finding]:
    findings = []
    for uid in case.appops.uids:
        per_package: dict[str, list[tuple[PackageOp, list[OpEvent]]]] = defaultdict(list)
        for package, op in _sensor_ops(uid):  # deliveries only: never MONITOR_* or GPS
            used = [e for e in op.events if e.kind == "access" and e.uid_state in OFF_SCREEN_STATES]
            if used:
                per_package[package].append((op, used))
        for package, items in per_package.items():
            items.sort(key=lambda item: SENSOR_OPS.index(item[0].op))
            uses = [
                {
                    "op": op.op,
                    "mode": uid.effective_mode(op),
                    "states": sorted({e.uid_state for e in used}),
                    "last": max(e.time for e in used).isoformat(sep=" ", timespec="seconds"),
                }
                for op, used in items
            ]
            states = {s for u in uses for s in u["states"]}
            where = join(
                (["in the background"] if states & {"bg", "cch"} else [])
                + (["from a foreground service"] if "fgsvc" in states else [])
            )
            ops = {str(u["op"]) for u in uses}
            # Camera or microphone in the background proper is a concern; from a
            # foreground service only, Android shows a notification and the privacy
            # indicator while it runs, so it's notable like location.
            av = [u for u in uses if u["op"] in CONCERN_OPS]
            hidden_av = any(set(u["states"]) & {"bg", "cch"} for u in av)
            evidence: list[EvidenceRef] = []
            for op, used in items:
                evidence += case.evidence(APPOPS_FILE, uid.mode_lines.get(op.switch_op or op.op))
                evidence += [r for e in used for r in case.evidence(APPOPS_FILE, e.line)]
            findings.append(
                make_finding(
                    spec,
                    case,
                    package,
                    f"{package} used {access_phrase(ops)} while it wasn't on screen ({where}), "
                    "and Android allowed it."
                    + (
                        " The camera and microphone were used only from a foreground service, "
                        "while Android shows a notification and the privacy indicator."
                        if av and not hidden_av
                        else ""
                    ),
                    facts={"uid": uid.uid, "uses": uses, "camera_mic_in_background": hidden_av},
                    evidence=evidence,
                    severity="concern" if hidden_av else None,
                )
            )
    return findings


@rule_function("sensor-use-summary")
def sensor_use_summary(case: CaseData, spec: RuleSpec) -> list[Finding]:
    findings = []
    uses: dict[str, list[dict[str, Any]]] = defaultdict(list)
    use_evidence: dict[str, list[EvidenceRef]] = defaultdict(list)
    for uid in case.appops.uids:
        for package, op in _sensor_ops(uid):
            for e in op.events:
                if e.kind != "access":
                    continue
                uses[package].append(
                    {
                        "op": op.op,
                        "state": e.uid_state,
                        "time": e.time.isoformat(sep=" "),
                        "duration": _fmt(e.duration) if e.duration else None,
                    }
                )
                use_evidence[package] += case.evidence(APPOPS_FILE, e.line)
    for agg in case.location.aggregates:
        uses[agg.package].append(
            {
                "op": f"location request ({agg.provider})",
                "provider": agg.provider,
                "total": _fmt(agg.total),
                "foreground": _fmt(agg.foreground),
                "background": _fmt(agg.background),
                "locations": agg.locations,
            }
        )
        use_evidence[agg.package] += case.evidence(LOCATION_FILE, agg.line)
    for package in sorted(uses):
        used = access_phrase(u["op"] for u in uses[package] if "state" in u)
        asked = any("provider" in u for u in uses[package])
        if used:
            summary = f"{package} used {used}" + (
                ", and asked for location updates." if asked else "."
            )
        else:
            summary = f"{package} asked for location updates."
        findings.append(
            make_finding(
                spec,
                case,
                package,
                summary,
                facts={"uses": uses[package]},
                evidence=use_evidence[package],
            )
        )
    # Location requests marked hiddenFromAppOps don't show in appops at all. They are
    # platform requests, so they always go to the system section.
    hidden: dict[str, list[Any]] = defaultdict(list)
    for provider in case.location.providers:
        for listener in provider.listeners:
            if listener.hidden_from_appops:
                hidden[listener.package].append((provider.name, listener))
    for package, items in sorted(hidden.items()):
        findings.append(
            make_finding(
                spec,
                case,
                package,
                f"{package} holds {len(items)} location "
                + ("request" if len(items) == 1 else "requests")
                + " that Android keeps out of the permission history, so Settings doesn't "
                "show them.",
                facts={
                    "requests": [
                        {"provider": p, "tag": li.tag, "request": li.request} for p, li in items
                    ]
                },
                evidence=[r for _, li in items for r in case.evidence(LOCATION_FILE, li.line)],
                force_system=True,
            )
        )
    return findings


# The sensitive ops appopsy checks (CLAUDE.md, Phase 1).
OVER_PRIVILEGE_OPS = (
    "RECORD_AUDIO", "CAMERA", "FINE_LOCATION", "COARSE_LOCATION", "READ_CONTACTS",
    "READ_CALL_LOG", "READ_SMS", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
    "READ_MEDIA_VISUAL_USER_SELECTED", "BODY_SENSORS", "RUN_ANY_IN_BACKGROUND",
)  # fmt: skip
_MODE_STRENGTH = {"allow": 2, "foreground": 1}


def _allowed_ops(uid: UidOps, package: str) -> dict[str, tuple[str, list[int | None]]]:
    """op -> (effective mode, evidence lines: UID mode and package op) for sensitive ops
    this package may use."""
    pkg = next(p for p in uid.packages if p.name == package)
    ops = {o.op: o for o in pkg.ops}
    out: dict[str, tuple[str, list[int | None]]] = {}
    for name in OVER_PRIVILEGE_OPS:
        if name in ops:
            mode = uid.effective_mode(ops[name])
        elif name in uid.modes:
            mode = uid.modes[name]
        else:
            continue  # not printed: unknown, not counted
        if mode in _MODE_STRENGTH:
            out[name] = (mode, [uid.mode_lines.get(name), ops[name].line if name in ops else None])
    return out


def _categories(ops: dict[str, str]) -> dict[str, dict[str, str]]:
    """Allowed ops -> per category: the broadest mode, and full or partial scope."""
    out = {}
    for cat in ACCESS_CATEGORIES:
        modes = {op: ops[op] for op in cat.ops if op in ops}
        if not modes:
            continue
        full = [op for op in modes if op in cat.full]
        scope_ops = full or list(modes)
        mode = max((modes[op] for op in scope_ops), key=lambda m: _MODE_STRENGTH[m])
        out[cat.key] = {"mode": mode, "scope": "full" if full else "partial"}
    return out


@rule_function("over-privileged-app")
def over_privileged_app(case: CaseData, spec: RuleSpec) -> list[Finding]:
    # One entry per package; a package under several UIDs keeps its broadest access.
    access: dict[str, dict[str, tuple[str, list[int | None]]]] = defaultdict(dict)
    pkg_lines: dict[str, list[int | None]] = defaultdict(list)
    for uid in case.appops.uids:
        for pkg in uid.packages:
            pkg_lines[pkg.name].append(pkg.line)
            for op, (mode, lines) in _allowed_ops(uid, pkg.name).items():
                known = access[pkg.name].get(op)
                if known is None or _MODE_STRENGTH[mode] > _MODE_STRENGTH[known[0]]:
                    access[pkg.name][op] = (mode, lines)
    cats = {p: _categories({op: m for op, (m, _) in ops.items()}) for p, ops in access.items()}

    def counted(package: str) -> dict[str, dict[str, str]]:
        # Selected photos only is the privacy-friendly choice: shown, not counted.
        return {k: v for k, v in cats.get(package, {}).items() if (k, v["scope"]) not in FRIENDLY}

    groups: dict[bool, list[str]] = {True: [], False: []}  # system? -> packages
    # Installed apps are ranked even with nothing allowed; others only when they
    # have something (a full dump lists hundreds).
    for package in pkg_lines:
        kind = case.classify(package)
        if counted(package) or kind == "user_installed":
            groups[kind == "system"].append(package)
    total = len(ACCESS_CATEGORIES)
    findings = []
    for is_system, packages in groups.items():

        def key(p: str) -> tuple[int, int, int, str]:
            c = counted(p).values()
            return (-len(c), -sum(v["mode"] == "allow" for v in c),
                    -sum(v["scope"] == "full" for v in c), p)  # fmt: skip

        ranked = sorted(packages, key=key)
        for rank, package in enumerate(ranked, start=1):
            ops = access[package]
            mine = counted(package)
            any_time = category_phrase(
                (k, v["scope"]) for k, v in mine.items() if v["mode"] == "allow"
            )
            in_use = category_phrase(
                (k, v["scope"]) for k, v in mine.items() if v["mode"] == "foreground"
            )
            scope = "system components" if is_system else "apps"
            parts = []
            if any_time:
                parts.append(f"{any_time} at any time")
            if in_use:
                parts.append(f"{in_use} only while it's in use")
            summary = (
                f"{package} is allowed {len(mine)} of the {total} kinds of sensitive access "
                f"appopsy checks: {'; '.join(parts)}."
                if mine
                else f"{package} isn't allowed any of the {total} kinds of sensitive access "
                "appopsy checks."
            )
            if ("photos_videos", "partial") in {
                (k, v["scope"]) for k, v in cats.get(package, {}).items()
            }:
                summary += " It can see only the photos and videos you picked."
            summary += f" It ranks {rank} of {len(ranked)} {scope}."
            lines_cited = [ln for _, lns in ops.values() for ln in lns] or pkg_lines[package]
            findings.append(
                make_finding(
                    spec,
                    case,
                    package,
                    summary,
                    facts={
                        "rank": rank,
                        "checked": total,
                        "of": len(ranked),
                        "scope": scope,
                        "count": len(mine),
                        "categories": cats.get(package, {}),
                        "allowed": {o: m for o, (m, _) in sorted(ops.items())},
                    },
                    evidence=[r for ln in lines_cited for r in case.evidence(APPOPS_FILE, ln)],
                )
            )
    return findings
