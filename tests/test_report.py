"""The Markdown report, against capture-5 and with hostile device strings."""

from __future__ import annotations

import importlib.util
import re
import shutil
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from appopsy.cli import app
from appopsy.report.build import build_report, evidence_lines
from appopsy.report.markdown import cell, code, github_slug, md, render_markdown
from appopsy.rules.case import CaseData
from appopsy.rules.engine import EvidenceRef, Finding, load_rules, run_rules

CAPTURES = Path(__file__).parent / "fixtures" / "17-google"
ROOT_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def report() -> str:
    case = CaseData(CAPTURES / "capture-5")
    specs = load_rules(packs=("privacy",))
    return render_markdown(build_report(case, specs, run_rules(case, specs)))


def section(text: str, heading: str) -> str:
    start = text.index(f"\n{heading}\n")
    end = text.find("\n## ", start + 1)
    return text[start : end if end != -1 else len(text)]


def prose(text: str) -> list[str]:
    """Lines a reader reads as sentences: not tables, evidence or the method notes."""
    text = text[: text.index("\n## How this report was made\n")]
    return [
        line
        for line in text.splitlines()
        if line.strip() and not line.startswith(("|", "Evidence:", "#"))
    ]


def test_sections_in_order(report: str) -> None:
    headings = [line for line in report.splitlines() if line.startswith("## ")]
    assert headings == [
        "## Summary",
        "## Privacy findings",
        "## Per-app detail",
        "## What you can do",
        "## System components",
        "## How this report was made",
        "## Appendix",
    ]
    appendices = [x for x in section(report, "## Appendix").splitlines() if x.startswith("### ")]
    assert appendices == [
        "### Sensitive access",
        "### Recent sensor use",
        "### Background jobs",
        "### System components",
    ]
    assert report.startswith("# appopsy report: Pixel 11 Pro\n")
    assert "Android 17 (SDK 37), security patch 2026-10-05" in report
    assert "Collected 2030-01-01 00:00 by the phone's clock" in report


def test_headline_comes_first_and_names_the_main_findings(report: str) -> None:
    top = report[: report.index("\n## Summary\n")]
    (headline,) = [p for p in top.split("\n\n") if p.startswith("Google Maps received")]
    assert 3 <= headline.count(". ") + 1 <= 4
    assert "tried to use your location in the background and were refused" in headline
    assert "Facebook (14) and Messenger (3) have background jobs" in headline  # not preinstalled
    assert "Google Maps received your location while not on screen." in headline
    assert "Google Maps, which came with the phone, has the broadest access: 6 of the 9" in headline


def test_friendly_names_with_the_package_in_brackets(report: str) -> None:
    assert "**Facebook (com.facebook.katana)** tried to use" in report
    assert "- **X (com.twitter.android)**, Google Play:" in report
    # Unknown packages fall back to the package name.
    assert "#### com.android.imsstack: Recent use of location" in report


def test_prose_has_no_op_constants_or_uid_states(report: str) -> None:
    for line in prose(report):
        assert not re.search(r"\b[A-Z]+_[A-Z_]+\b", line), line
        assert not re.search(r"\((?:bg|cch|fg|top|fgsvc)(?:, \w+)*\)", line), line
    # Tables keep the constants.
    assert "| precise location (FINE_LOCATION) | only while in use |" in report


def test_summary_counts_and_origins(report: str) -> None:
    summary = section(report, "## Summary")
    assert "| Notable | 6 |" in summary and "| Info | 11 |" in summary  # Maps' jobs: info
    assert "| System components (listed separately) | 13 |" in summary  # +1: ASI background use
    assert "7 apps have findings; [Per-app detail](#per-app-detail) lists them" in summary
    apps = section(report, "## Per-app detail")
    assert "- **WhatsApp (com.whatsapp)**, Google Play: " in apps
    assert "- **Google Maps (com.google.android.apps.maps)**, came with the phone: " in apps


def test_access_ranking_is_one_table_with_detail_for_any_time_apps(report: str) -> None:
    findings = section(report, "## Privacy findings")
    ranking = findings[findings.index("#### Sensitive access each app is allowed") :]
    ranking = ranking[: ranking.index("**Probably harmless:**")]
    rows = [
        x.split(" | ")[0].lstrip("| ")
        for x in ranking.splitlines()
        if x.startswith("| ") and "(" in x
    ]
    assert rows == [
        "Google Maps (com.google.android.apps.maps)",  # came with the phone, ranked with the rest
        "WhatsApp (com.whatsapp)",
        "Phone (com.google.android.dialer)",
        "Facebook (com.facebook.katana)",
        "Messenger (com.facebook.orca)",
        "WeChat (com.tencent.mm)",
        "1 more app (listed in the appendix)",  # X: nothing sensitive
    ]
    assert (
        "| Google Maps (com.google.android.apps.maps) | 6: location, camera, microphone, "
        "contacts, photos and videos, running in the background | 3 |" in ranking
    )
    assert (
        "| Facebook (com.facebook.katana) | 2: location, camera | — |" in ranking
    )  # selected photos: not counted
    assert "**Google Maps" not in ranking  # no block per app in the main report
    detail = section(report, "## Appendix")
    detail = detail[detail.index("### Sensitive access") : detail.index("### Recent sensor use")]
    entries = [x[5:] for x in detail.splitlines() if x.startswith("#### ")]
    assert entries == [  # only apps allowed something at any time, in rank order
        "Google Maps (com.google.android.apps.maps)",
        "WhatsApp (com.whatsapp)",
        "Phone (com.google.android.dialer)",
        "No sensitive access",  # then the apps allowed none of it
    ]
    assert (
        "your precise location, contacts, photos and videos, plus running in the background "
        "at any time" in detail
    )
    assert "| Location (FINE_LOCATION, COARSE_LOCATION) | at any time | precise |" in detail


def test_only_platform_components_in_the_system_section(report: str) -> None:
    platform = ("com.google.android.gms", "com.google.android.as", "(android)")
    for heading in ("## Privacy findings", "## Per-app detail", "## What you can do"):
        body = section(report, heading)
        assert not any(p in body for p in platform), heading
    system = section(report, "## System components")
    assert all(p in system for p in platform)
    assert "com.google.android.apps.maps" not in system and "dialer" not in system
    # One row per finding, naming how many components and the first few.
    assert "| Finding | Components |" in system
    assert "Each finding in full: [appendix](#system-components-1)." in system


def test_repetition_is_trimmed(report: str) -> None:
    findings = section(report, "## Privacy findings")
    jobs = findings[findings.index("#### Background work that can run at any time") :]
    jobs = jobs[: jobs.index("**Probably harmless:**")]
    assert (  # installed apps: one table, a few job names each
        "| Facebook (com.facebook.katana) | 14 | IdentityHashWorker, "
        "OfflineFeedBackgroundPrefetchWorker, NotificationsPermissionWorker, ... |" in jobs
    )
    assert (
        "| Messenger (com.facebook.orca) | 3 | EarlyAccessSyncWorker, SimCarrierInfoLogWorker, LollipopUploadService |"
        in jobs
    )
    appendix = section(report, "## Appendix")
    assert (
        "has 14 background jobs that can run without charging, the phone being idle or Wi-Fi, "
        "including IdentityHashWorker, OfflineFeedBackgroundPrefetchWorker, "
        "NotificationsPermissionWorker and 11 more." in appendix
    )
    assert "| FFJobService | a deadline, any network |" in appendix  # last component only
    assert "com.facebook.falco" not in report and "a delay" not in report
    assert "| NotificationsPermissionWorker | — |" in appendix  # empty cell
    assert "| Count |" not in appendix  # no repeated job in this capture: column dropped


def test_apps_that_came_with_the_phone_get_one_compact_jobs_table(report: str) -> None:
    findings = section(report, "## Privacy findings")
    info = findings[findings.index("### Info") :]
    jobs = info[info.index("#### Background work that can run at any time") :]
    jobs = jobs[: jobs.index("**Probably harmless:**")]
    assert "Details: [appendix](#background-jobs)." in jobs
    assert "| App | Jobs |\n|---|---|\n| Google Maps (com.google.android.apps.maps) | 1 |" in jobs
    appendix = section(report, "## Appendix")
    assert "#### Google Maps (com.google.android.apps.maps)\n\nhas 1 background job" in appendix
    assert "| GmmWorkerWrapper |" in appendix
    todo = section(report, "## What you can do")
    assert "Google Maps (1)" not in todo  # came with the phone: general steps only


def test_what_you_can_do_gives_a_concrete_step_per_app(report: str) -> None:
    todo = section(report, "## What you can do")
    for line in todo.splitlines():
        if re.match(r"^- [A-Z][\w ]+: ", line):  # an app-specific line
            assert ": Settings > Apps > " in line, line  # names where to go
    assert (
        "- Settings > Apps > (the app) > App battery usage: choose Restricted to defer its "
        "background jobs. Most jobs first: Facebook (14), Messenger (3)." in todo
    )
    assert "- Google Maps: Settings > Apps > Google Maps > Permissions: set Contacts to" in todo
    assert "- Phone:" not in todo  # contacts and call log are what a phone app is for
    assert "- X:" not in todo  # allowed nothing: nothing to narrow
    # Selected photos only is the privacy-friendly choice: never an action.
    fb = [x for x in todo.splitlines() if x.startswith("- Facebook:")]
    assert fb and not any("Photos" in x for x in fb)
    assert "Settings > Apps > (the app) > App battery usage" in todo  # general steps follow


def test_background_sensor_use_in_the_report(report: str) -> None:
    findings = section(report, "## Privacy findings")
    block = findings[findings.index("#### Used a sensor while not on screen") :]
    assert block.index("**Google Maps (com.google.android.apps.maps)** used your precise location")
    assert (
        "| precise location (FINE_LOCATION) | at any time | in the background, cached in the "
        "background, foreground service | 2029-12-31 23:59:00 |" in block
    )
    # It sits with the notable findings, above the info-level sensor summary.
    assert findings.index("#### Used a sensor while not on screen") < findings.index("### Info")


def test_per_app_list_sorted_and_linked(report: str) -> None:
    apps = section(report, "## Per-app detail")
    rows = [x[4 : x.index("**", 4)] for x in apps.splitlines() if x.startswith("- **")]
    assert rows == [
        "Facebook (com.facebook.katana)",  # notable, 4 (ties with Maps: by name)
        "Google Maps (com.google.android.apps.maps)",
        "WhatsApp (com.whatsapp)",  # notable, 3
        "Messenger (com.facebook.orca)",
        "WeChat (com.tencent.mm)",
        "Phone (com.google.android.dialer)",  # info
        "X (com.twitter.android)",
    ]
    # Links resolve to the GitHub anchors of the rule sections, repeats counted.
    slugs = {github_slug(x.lstrip("# ")) for x in report.splitlines() if x.startswith("#")}
    maps = next(x for x in apps.splitlines() if x.startswith("- **Google Maps"))
    assert (
        "[Background work that can run at any time](#background-work-that-can-run-at-any-time-1) (info)"
        in maps
    )
    for target in re.findall(r"\]\(#([\w-]+)\)", apps):
        assert target.rstrip("-0123456789") in slugs or target in slugs, target
    assert "@@" not in report
    assert "| Location fixes delivered |" in report


def test_play_services_wakeups_are_explained(report: str) -> None:
    system = section(report, "## System components")
    line = next(x for x in system.splitlines() if x.startswith("- **Google Play services"))
    assert "notifications and runs sync for many apps" in line and "restrict it" in line
    appendix = section(report, "## Appendix")
    assert "#### Google Play services (com.google.android.gms): Wakes the phone often" in appendix


def test_evidence_is_cited(report: str) -> None:
    findings = section(report, "## Privacy findings")
    assert findings.count("**Why it matters:**") == findings.count("#### ") == 6
    assert "Evidence: dumpsys-appops.txt: lines 916, 917, 969, 970, 976, 977" in findings
    assert "and 6 more" in section(report, "## Appendix")  # 14 job blocks, 8 shown


def test_method_cites_threshold_sources(report: str) -> None:
    method = section(report, "## How this report was made")
    assert "(https://support.google.com/googleplay/android-developer/answer/7385505)" in method
    assert "checked 2026-11-01, verified." in method
    assert "No threshold: There is no published guidance" in method
    assert "No threshold: No threshold" not in method and "no threshold on purpose" not in method


def test_no_html_in_the_report(report: str) -> None:
    for line in report.splitlines():
        assert "<" not in line.replace("\\<", ""), line


def test_device_strings_cannot_inject_markdown() -> None:
    hostile = "com.example.app|<script>*x*</script>[a](b)`_y_"
    assert md(hostile) == r"com.example.app\|\<script>\*x\*\</script>\[a\](b)\`\_y\_"
    assert md("Settings > Apps") == "Settings > Apps"
    assert md("FINE_LOCATION") == "FINE_LOCATION"  # intraword: left readable
    assert cell("a|b\nc") == r"a\|b c" and cell("") == " "
    assert code("plain") == "`plain`"
    assert code("a`b") == "`` a`b ``"


def test_evidence_lines_group_and_cap() -> None:
    refs = [EvidenceRef(file="b.txt", start=n, end=n) for n in range(1, 12)]
    refs += [EvidenceRef(file="a.txt", start=5, end=9), EvidenceRef(file="a.txt", start=5, end=9)]
    assert evidence_lines(refs) == [
        "a.txt: lines 5-9",
        "b.txt: lines 1, 2, 3, 4, 5, 6, 7, 8 and 3 more",
    ]
    assert evidence_lines([EvidenceRef(file="c.txt", start=3, end=3)]) == ["c.txt: line 3"]


def test_secondary_uid_is_labelled() -> None:
    """com.google.android.as also appears under UID 30168 (capture-1): label it."""
    case = CaseData(CAPTURES / "capture-1")
    (spec,) = [s for s in load_rules() if s.id == "background-sensor-attempt"]
    finding = Finding(
        rule_id=spec.id, pack="privacy", severity="info", title=spec.title,
        package="com.google.android.as", app_class="system", section="system",
        summary="com.google.android.as tried something.", facts={"uid": 30168, "attempts": []},
    )  # fmt: skip
    text = render_markdown(build_report(case, [spec], [finding]))
    assert "Android System Intelligence (com.google.android.as, secondary UID 30168)" in text
    own = finding.model_copy(update={"facts": {"uid": 10168, "attempts": []}})
    assert "secondary UID" not in render_markdown(build_report(case, [spec], [own]))


def test_cli_writes_a_private_report_into_the_case_folder(tmp_path: Path) -> None:
    case = tmp_path / "case"
    shutil.copytree(CAPTURES / "capture-5", case / "raw")
    result = CliRunner().invoke(app, ["report", str(case)])
    assert result.exit_code == 0, result.output
    out = case / "report" / "report.md"
    assert out.read_text().startswith("# appopsy report:")
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert stat.S_IMODE(out.parent.stat().st_mode) == 0o700


def test_cli_prints_a_capture_report_and_checks_the_pack() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["report", str(CAPTURES / "capture-5"), "--pack", "all"])
    assert result.exit_code == 0
    assert "## Security findings\n\nNo security rules are available yet." in result.output
    assert runner.invoke(app, ["report", str(CAPTURES / "capture-5"), "--pack", "x"]).exit_code == 2


def test_job_names_several_apps_share_are_collapsed(report: str) -> None:
    """Facebook and Messenger both schedule SimCarrierInfoLogWorker (capture-5)."""
    appendix = section(report, "## Appendix")
    shared = appendix[appendix.index("#### Shared job libraries") :]
    assert (
        "| a library several apps share | SimCarrierInfoLogWorker | 2 | Facebook, Messenger |"
        in shared
    )
    assert "| a library several apps share: SimCarrierInfoLogWorker | any network |" in appendix


def test_repeats_merge_and_known_libraries_are_named() -> None:
    case = CaseData(CAPTURES / "capture-5")
    (spec,) = [s for s in load_rules() if s.id == "unconstrained-background-work"]
    job = {"what": "GnpWorker", "requires": ["TIMING_DELAY", "ANY_NETWORK"], "periodic": None}

    def finding(package: str, n: int) -> Finding:
        return Finding(
            rule_id=spec.id, pack="privacy", severity="notable", title=spec.title,
            package=package, summary=f"{package} has jobs.", facts={"jobs": [job] * n},
        )  # fmt: skip

    fs = [finding("com.whatsapp", 4), finding("com.facebook.katana", 1)]
    text = render_markdown(build_report(case, [spec], fs))
    assert "| Google Notifications Platform: GnpWorker | 4 | any network |" in text
    assert "| Google Notifications Platform | GnpWorker | 2 | Facebook, WhatsApp |" in text


@pytest.mark.parametrize("name", ["sample-report.md", "sample-report.html"])
def test_readme_sample_report_is_current(name: str) -> None:
    """docs/sample-report.* must match a fresh render (capture-5, redacted, with the
    sample's fixed alias key). Regenerate: uv run python scripts/make_sample_report.py"""
    spec = importlib.util.spec_from_file_location(
        "make_sample_report", ROOT_DIR / "scripts" / "make_sample_report.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    markdown, html = module.render()
    expected = html if name.endswith(".html") else markdown
    committed = (ROOT_DIR / "docs" / name).read_text()
    assert committed == expected, f"docs/{name} is stale; regenerate it (see docstring)"


def _use(package: str, op: str, states: list[str], severity: str) -> Finding:
    (spec,) = [s for s in load_rules() if s.id == "background-sensor-use"]
    return Finding(
        rule_id=spec.id, pack="privacy", severity=severity, title=spec.title,
        package=package, summary=f"{package} used something.",
        facts={"uid": 10500, "uses": [
            {"op": op, "mode": "allow", "states": states, "last": "2029-12-31 23:00:00"}
        ]},
    )  # fmt: skip


def test_headline_scales_and_never_merges_sensors_across_apps() -> None:
    """A second real phone: eight apps used location while not on screen, and only
    one of them the microphone. The headline must not say the eight used the mic."""
    case = CaseData(CAPTURES / "capture-5")
    specs = load_rules(packs=("privacy",))
    findings = [
        _use(f"org.example.app{i}", "FINE_LOCATION", ["bg"], "notable") for i in range(1, 9)
    ]
    findings.append(_use("org.example.recorder", "RECORD_AUDIO", ["cch"], "concern"))
    lines = build_report(case, specs, findings).headline
    assert lines[0] == (  # concern first, naming only the app that used it
        "org.example.recorder used the microphone in the background, where nothing on screen "
        "shows it."
    )
    assert lines[1] == (
        "org.example.app1, org.example.app2, org.example.app3 and 5 more received your "
        "location while not on screen."
    )
    for line in lines:
        assert not ("microphone" in line and "location" in line), line
    # A foreground-service microphone use is its own, notable sentence.
    findings.append(_use("org.example.caller", "RECORD_AUDIO", ["fgsvc"], "notable"))
    lines = build_report(case, specs, findings).headline
    assert "org.example.caller used the microphone from a foreground service" in lines[1]
    assert "org.example.caller" not in lines[0]


def test_headline_attempts_are_one_sentence_per_sensor() -> None:
    case = CaseData(CAPTURES / "capture-5")
    (spec,) = [s for s in load_rules() if s.id == "background-sensor-attempt"]

    def attempt(package: str, op: str) -> Finding:
        return Finding(
            rule_id=spec.id, pack="privacy", severity="notable", title=spec.title,
            package=package, summary=f"{package} tried.",
            facts={"uid": 10500, "attempts": [{"op": op, "mode": "foreground",
                   "rejected_in": ["bg"], "last_reject": "2029-12-31 23:00:00"}]},
        )  # fmt: skip

    fs = [attempt(f"org.example.app{i}", "COARSE_LOCATION") for i in range(1, 6)]
    fs.append(attempt("org.example.cam", "CAMERA"))
    lines = build_report(case, [spec], fs).headline
    assert lines == [
        "org.example.cam tried to use the camera in the background and was refused, because "
        "your settings allow it only while the app is in use.",
        "org.example.app1, org.example.app2, org.example.app3 and 2 more tried to use your "
        "location in the background and were refused, because your settings allow it only "
        "while the app is in use.",
    ]


def test_report_and_audit_announce_files_the_same_way(tmp_path: Path) -> None:
    case = tmp_path / "case"
    shutil.copytree(CAPTURES / "capture-5", case / "raw")
    out = CliRunner().invoke(app, ["report", str(case)]).output
    md, html = case / "report" / "report.md", (case / "report" / "report.html")
    assert out.splitlines() == [
        f"Written: {md}",
        f"Written: {html}",
        f"Open your report: {html.resolve()}",
    ]
    shared = CliRunner().invoke(app, ["report", str(case), "--redact"]).output
    assert f"Open your report: {(case / 'report' / 'report-redacted.html').resolve()}" in shared


def test_developer_commands_are_hidden_but_work() -> None:
    runner = CliRunner()
    listing = runner.invoke(app, ["--help"]).output
    for shown in ("devices", "audit", "report"):
        assert shown in listing
    for hidden in ("redact-fixture", "mask"):
        assert hidden not in listing
        assert runner.invoke(app, [hidden, "--help"]).exit_code == 0


def test_core_access_is_never_suggested_for_removal(report: str) -> None:
    """Location is what Maps is for (`core:` in apps.yaml): no step touches it."""
    todo = section(report, "## What you can do")
    maps = [x for x in todo.splitlines() if x.startswith("- Google Maps:")]
    assert maps and not any("Location" in x for x in maps)
    phone = [x for x in todo.splitlines() if x.startswith("- Phone:")]
    assert not any("Contacts" in x or "Call logs" in x for x in phone)


def test_headline_merges_one_apps_sensors_with_the_same_visibility() -> None:
    """The Google app used the microphone and camera from a foreground service: one
    sentence, with its sentence name; another app's microphone stays separate."""
    case = CaseData(CAPTURES / "capture-5")
    specs = load_rules(packs=("privacy",))
    g = "com.google.android.googlequicksearchbox"
    fs = [
        _use(g, "RECORD_AUDIO", ["fgsvc"], "notable"),
        _use("org.example.voice", "RECORD_AUDIO", ["fgsvc"], "notable"),
    ]
    fs[0].facts["uses"].append(
        {"op": "CAMERA", "mode": "foreground", "states": ["fgsvc"], "last": "2029-12-31 23:00:00"}
    )
    lines = build_report(case, specs, fs).headline
    assert (
        "The Google app used the microphone and the camera from a foreground service, which "
        "shows a notification while it runs."
    ) in lines
    assert (
        "org.example.voice used the microphone from a foreground service, which shows a "
        "notification while it runs."
    ) in lines


def test_battery_step_names_the_top_five_then_counts() -> None:
    case = CaseData(CAPTURES / "capture-5")
    (spec,) = [s for s in load_rules() if s.id == "unconstrained-background-work"]
    fs = [
        Finding(
            rule_id=spec.id,
            pack="privacy",
            severity="notable",
            title=spec.title,
            package=f"org.example.app{i}",
            summary=f"org.example.app{i} has jobs.",
            facts={
                "jobs": [{"what": f"Job{j}", "requires": [], "periodic": None} for j in range(i)],
                "undetermined": 0,
            },
        )
        for i in range(1, 9)
    ]
    text = render_markdown(build_report(case, [spec], fs))
    line = next(x for x in text.splitlines() if "Most jobs first:" in x)
    assert line.endswith(
        "org.example.app8 (8), org.example.app7 (7), org.example.app6 (6), "
        "org.example.app5 (5), org.example.app4 (4) and 3 more (see the table above)."
    )


def test_apps_with_no_sensitive_access_collapse_into_one_row(report: str) -> None:
    findings = section(report, "## Privacy findings")
    ranking = findings[findings.index("#### Sensitive access each app is allowed") :]
    ranking = ranking[: ranking.index("**Probably harmless:**")]
    assert "| 1 more app (listed in the appendix) | none | — |" in ranking  # X
    assert "X (com.twitter.android)" not in ranking
    appendix = section(report, "## Appendix")
    assert "#### No sensitive access\n\n1: X (com.twitter.android)." in appendix
