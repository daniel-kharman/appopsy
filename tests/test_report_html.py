"""The HTML report: same view model as Markdown, self-contained, escaped."""

from __future__ import annotations

import re
import shutil
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from appopsy.cli import app
from appopsy.report.build import build_report
from appopsy.report.html import render_html, rule_text
from appopsy.rules.case import CaseData
from appopsy.rules.engine import Finding, load_rules, run_rules

CAPTURE = Path(__file__).parent / "fixtures" / "17-google" / "capture-5"


@pytest.fixture(scope="module")
def html() -> str:
    case = CaseData(CAPTURE)
    specs = load_rules(packs=("privacy",))
    return render_html(build_report(case, specs, run_rules(case, specs)))


def test_self_contained_nothing_loaded_from_the_network(html: str) -> None:
    assert html.startswith("<!doctype html>")
    for banned in ("<script", "<link", "<img", "<iframe", "@import", "url(", " src="):
        assert banned not in html, banned
    # Links appear only as threshold citations the reader can choose to follow.
    hrefs = [h for h in re.findall(r'href="([^"]+)"', html) if not h.startswith("#")]
    assert hrefs == [
        "https://support.google.com/googleplay/android-developer/answer/7385505",
        "https://www.wikidata.org",  # the names credit
    ]
    assert '<meta name="referrer" content="no-referrer">' in html


def test_same_content_as_the_markdown_report(html: str) -> None:
    assert "<h1>appopsy report: Pixel 11 Pro</h1>" in html
    ids = re.findall(r'<h2 id="(\w+)">', html)
    assert ids == ["summary", "privacy", "apps", "actions", "system", "method", "appendix"]
    assert '<p class="headline">Google Maps received your location while not on screen.' in html
    assert "<strong>Google Maps (com.google.android.apps.maps)</strong> used your precise" in html
    assert "<td>precise location (FINE_LOCATION)</td>" in html
    assert "Settings &gt; Apps &gt; (the app) &gt; App battery usage" in html
    assert "Apps and their jobs: Facebook (14), Messenger (3)." in html
    assert '<a href="#rule-background-sensor-attempt-notable">' in html  # per-app links
    assert '<h4 id="rule-background-sensor-attempt-notable">' in html
    assert 'class="badge sev-notable">notable</span>' in html
    # Light and dark themes from the same tokens.
    assert "@media (prefers-color-scheme: dark)" in html


def test_device_strings_are_escaped() -> None:
    case = CaseData(CAPTURE)
    (spec,) = [s for s in load_rules() if s.id == "unconstrained-background-work"]
    hostile = "org.example.<img src=x onerror=alert(1)>"
    f = Finding(
        rule_id=spec.id, pack="privacy", severity="notable", title=spec.title,
        package="org.example.app", summary="org.example.app has 1 job: x.",
        facts={"jobs": [{"what": hostile, "requires": [], "periodic": None}], "undetermined": 0},
    )  # fmt: skip
    out = render_html(build_report(case, [spec], [f]))
    assert "<img" not in out and "&lt;img src=x onerror=alert(1)&gt;" in out


def test_rule_text_escapes_then_marks_code() -> None:
    assert str(rule_text("ranks at `info` <b>")) == "ranks at <code>info</code> &lt;b&gt;"


def test_cli_writes_both_formats_into_the_case_folder(tmp_path: Path) -> None:
    case = tmp_path / "case"
    shutil.copytree(CAPTURE, case / "raw")
    result = CliRunner().invoke(app, ["report", str(case)])
    assert result.exit_code == 0, result.output
    for name in ("report.md", "report.html"):
        path = case / "report" / name
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, name
    assert (case / "report" / "report.html").read_text().startswith("<!doctype html>")
    out = tmp_path / "x.html"
    assert CliRunner().invoke(app, ["report", str(CAPTURE), "-o", str(out)]).exit_code == 0
    assert out.read_text().startswith("<!doctype html>")


def test_appendices_and_long_tables_fold_into_details(html: str) -> None:
    appendix = html[html.index('<h2 id="appendix">') :]
    assert appendix.count('<details id="appendix-') == 4  # one per appendix, folded
    # Facebook's 14 jobs exceed the 10-row limit: folded, with a row count.
    assert "<details><summary>14 rows</summary>" in html
    assert "<script" not in html
