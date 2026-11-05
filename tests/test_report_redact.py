"""--redact: unlisted apps get per-render aliases; their inner names and any device
identifier keep the report from being written."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from appopsy.cli import app
from appopsy.report.build import build_report, known_apps
from appopsy.report.markdown import render_markdown
from appopsy.report.redaction import RedactionError, check, plan
from appopsy.rules.case import CaseData
from appopsy.rules.engine import load_rules, run_rules

CAPTURE = Path(__file__).parent / "fixtures" / "17-google" / "capture-5"
PRIVATE = "com.example.bank"
WORKER = "com.example.bank.sync.BankStatementSyncWorker"


@pytest.fixture
def case_dir(tmp_path: Path) -> Path:
    """capture-5 plus one app that isn't on the public list, with a job and an alarm
    whose names contain the app's name, installed from a third-party store."""
    raw = tmp_path / "case" / "raw"
    shutil.copytree(CAPTURE, raw)
    with (raw / "pm-list-packages-3p.txt").open("a") as fh:
        fh.write(f"package:{PRIVATE}  installer=org.example.store\n")
    jobs = (raw / "dumpsys-jobscheduler.txt").read_text()
    block = (
        f"  JOB #u0a501/77: abc123 {PRIVATE}/androidx.work.impl.background.systemjob.SystemJobService\n"
        f"    Source: uid=u0a501 user=0 pkg={PRIVATE}\n"
        "    JobInfo:\n"
        f"      Service: {PRIVATE}/androidx.work.impl.background.systemjob.SystemJobService\n"
        "      Network type: any\n"
        f"      Trace tag: {WORKER}\n"
        "    Required constraints: TIMING_DELAY CONNECTIVITY [0x90200000]\n"
    )
    header = next(line for line in jobs.splitlines() if line.startswith("Registered "))
    (raw / "dumpsys-jobscheduler.txt").write_text(
        jobs.replace(header + "\n", header + "\n" + block, 1)
    )
    return tmp_path / "case"


def render(case: CaseData, key: bytes | None = None) -> tuple[str, object]:
    specs = load_rules(packs=("privacy",))
    findings = run_rules(case, specs)
    redaction = plan(case, findings, public=set(known_apps()), key=key)
    text = render_markdown(build_report(case, specs, findings, ("privacy",), redaction))
    return text, redaction


def test_unlisted_apps_are_aliased_and_their_names_hidden(case_dir: Path) -> None:
    case = CaseData(case_dir / "raw")
    text, redaction = render(case, key=b"k" * 32)
    check(text, redaction)  # type: ignore[arg-type]
    for leak in (PRIVATE, "BankStatementSyncWorker", "org.example.store"):
        assert leak not in text, leak
    alias = redaction.aliases[PRIVATE]  # type: ignore[attr-defined]
    assert alias.startswith("Unlisted app ") and f"| {alias} | 1 | (hidden) |" in text
    assert f"#### {alias}\n\nhas 1 background job" in text  # appendix entry
    assert "(names hidden)" in text and "| (hidden) |" in text
    assert "Redacted copy for sharing." in text and "1 app(s)" in text
    # Public apps keep their names; the allowlisted installer store is shown generically.
    assert "Facebook (com.facebook.katana)" in text and "Google Maps" in text
    assert "another app store" in text


def test_aliases_change_with_every_render(case_dir: Path) -> None:
    case = CaseData(case_dir / "raw")
    _, a = render(case)
    _, b = render(case)
    assert a.aliases[PRIVATE] != b.aliases[PRIVATE]  # type: ignore[attr-defined]


def test_check_refuses_leftovers_without_echoing_them(case_dir: Path) -> None:
    case = CaseData(case_dir / "raw")
    text, redaction = render(case)
    with pytest.raises(RedactionError, match="1 private name") as exc:
        check(text + f"\n{PRIVATE}\n", redaction)  # type: ignore[arg-type]
    assert PRIVATE not in str(exc.value)
    with pytest.raises(RedactionError, match=r"identifier\(s\) \(email"):
        check(text + "\nreach me at someone@gmail.com\n", redaction)  # type: ignore[arg-type]


def test_unredacted_report_is_unchanged(case_dir: Path) -> None:
    case = CaseData(case_dir / "raw")
    specs = load_rules(packs=("privacy",))
    text = render_markdown(build_report(case, specs, run_rules(case, specs)))
    assert PRIVATE in text and "Redacted copy" not in text


def test_cli_report_redact_writes_the_shareable_copy(case_dir: Path) -> None:
    result = CliRunner().invoke(app, ["report", str(case_dir), "--redact"])
    assert result.exit_code == 0, result.output
    out = case_dir / "report" / "report-redacted.md"
    assert PRIVATE not in out.read_text() and "Unlisted app" in out.read_text()
    assert not (case_dir / "report" / "report.md").exists()  # only what was asked for


def test_names_public_apps_share_are_not_secrets(case_dir: Path) -> None:
    """Library job names (GnpWorker, SyncJobService) that public apps also show reveal
    nothing about which unlisted app uses them, so they don't block the report."""
    jobs = case_dir / "raw" / "dumpsys-jobscheduler.txt"
    text = jobs.read_text().replace(WORKER, "androidx.work.impl.SystemJobService")
    jobs.write_text(text)
    case = CaseData(case_dir / "raw")
    specs = load_rules(packs=("privacy",))
    findings = run_rules(case, specs)
    # Facebook (public) shows the same job name.
    fb = next(f for f in findings if f.rule_id == "unconstrained-background-work"
              and f.package == "com.facebook.katana")  # fmt: skip
    fb.facts["jobs"].append({"what": "SystemJobService", "requires": [], "periodic": None})
    redaction = plan(case, findings, public=set(known_apps()))
    assert "SystemJobService" not in redaction.hidden
    assert PRIVATE in redaction.hidden


def test_check_matches_whole_names_only() -> None:
    from appopsy.report.redaction import Redaction

    redaction = Redaction({}, hidden={"AnalyticsWorker", "com.example.bank"})
    check("| NotificationAnalyticsWorker | any network |\n", redaction)  # inside a longer name
    check("com.example.banking is another app\n", redaction)
    with pytest.raises(RedactionError):
        check("| AnalyticsWorker | any network |\n", redaction)
    with pytest.raises(RedactionError):
        check("**com.example.bank** has 1 job.\n", redaction)


def test_redacted_html_shares_aliases_and_is_checked(case_dir: Path) -> None:
    from appopsy.report.run import analyse

    rendered = analyse(case_dir / "raw", "privacy").render(redact=True)
    assert PRIVATE not in rendered.html and "BankStatementSyncWorker" not in rendered.html
    alias = re.search(r"Unlisted app [0-9a-f]{6}", rendered.markdown)
    assert alias and alias.group(0) in rendered.html  # one render, one set of aliases


def test_cli_report_redact_on_a_case_writes_both_formats(case_dir: Path) -> None:
    result = CliRunner().invoke(app, ["report", str(case_dir), "--redact"])
    assert result.exit_code == 0, result.output
    for name in ("report-redacted.md", "report-redacted.html"):
        assert PRIVATE not in (case_dir / "report" / name).read_text(), name


def test_redacted_times_are_relative_days(case_dir: Path) -> None:
    from appopsy.report.run import analyse

    analysis = analyse(case_dir / "raw", "privacy")
    full, shared = analysis.render(), analysis.render(redact=True)
    exact = re.compile(r"\b\d{4}-\d\d-\d\d[ T]\d\d:\d\d")
    assert exact.search(full.markdown)  # the owner's own copy keeps exact times
    for text in (shared.markdown, shared.html):
        assert not exact.search(text)
    assert "Collected on a date not shown in this copy" in shared.markdown
    # capture-5 was taken at 00:00, so the evening before is "yesterday" (calendar days).
    assert "| in the background, cached in the background | yesterday |" in shared.markdown
    assert "| in the background | 2 days ago |" in shared.markdown


def test_check_refuses_an_exact_time() -> None:
    from appopsy.report.redaction import Redaction

    with pytest.raises(RedactionError, match="1 exact time"):
        check("| last used | 2029-12-31 23:59:00 |\n", Redaction({}))
    check("security patch 2026-10-05\n", Redaction({}))  # a date alone is fine
