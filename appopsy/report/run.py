"""Make a report for a case folder: parse, run the rules, render, write privately."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from appopsy import __version__
from appopsy.report.build import build_report, known_apps
from appopsy.report.html import render_html
from appopsy.report.markdown import render_markdown
from appopsy.report.redaction import check, plan
from appopsy.rules.case import CaseData
from appopsy.rules.engine import Finding, RuleSpec, load_rules, run_rules

PACKS: dict[str, tuple[str, ...]] = {
    "privacy": ("privacy",),
    "security": ("security",),
    "all": ("privacy", "security"),
}
REPORT_DIR = "report"
MARKDOWN_NAME = "report.md"
REDACTED_NAME = "report-redacted.md"
HTML_NAME = "report.html"
REDACTED_HTML_NAME = "report-redacted.html"
PARSED_DIR = "parsed"
FINDINGS_NAME = "findings.json"


@dataclass(frozen=True)
class Rendered:
    markdown: str
    html: str


@dataclass
class Analysis:
    case: CaseData
    packs: tuple[str, ...]
    specs: list[RuleSpec]
    findings: list[Finding]

    @property
    def warnings(self) -> int:
        return len(self.case.warnings)

    def render(self, redact: bool = False) -> Rendered:
        """Markdown and HTML from one view model (so a redacted pair shares its aliases).
        ``redact``: the shareable copy, both texts checked before they're returned
        (raises RedactionError if anything private is left)."""
        redaction = plan(self.case, self.findings, public=set(known_apps())) if redact else None
        report = build_report(self.case, self.specs, self.findings, self.packs, redaction)
        rendered = Rendered(render_markdown(report), render_html(report))
        if redaction is not None:
            check(rendered.markdown, redaction)
            check(rendered.html, redaction)
        return rendered

    def markdown(self, redact: bool = False) -> str:
        return self.render(redact).markdown

    def findings_json(self) -> str:
        """The parsed findings, for tools (and Phase 4's --llm): never raw lines."""
        data = {
            "appopsy_version": __version__,
            "packs": list(self.packs),
            "findings": [f.model_dump(mode="json") for f in self.findings],
            "parse_warnings": [
                {"source": w.source, "line": w.line, "message": w.message}
                for w in self.case.warnings
            ],
        }
        return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def analyse(raw_dir: Path, pack: str) -> Analysis:
    """Parse a raw folder and run the pack's rules."""
    case = CaseData(raw_dir)
    specs = load_rules(packs=PACKS[pack])
    analysis = Analysis(case, PACKS[pack], specs, run_rules(case, specs))
    analysis.markdown()  # parses everything, so `warnings` is complete
    return analysis


def write_case_outputs(root: Path, analysis: Analysis, redact: bool = False) -> list[Path]:
    """<case>/report/report.{md,html} and <case>/parsed/findings.json, written privately;
    with ``redact`` also report-redacted.{md,html}. Everything is rendered (and the
    redacted copy checked) before anything is written."""
    full = analysis.render()
    outputs = [
        (root / REPORT_DIR / MARKDOWN_NAME, full.markdown),
        (root / REPORT_DIR / HTML_NAME, full.html),
        (root / PARSED_DIR / FINDINGS_NAME, analysis.findings_json()),
    ]
    if redact:
        shared = analysis.render(redact=True)
        outputs += [
            (root / REPORT_DIR / REDACTED_NAME, shared.markdown),
            (root / REPORT_DIR / REDACTED_HTML_NAME, shared.html),
        ]
    for path, text in outputs:
        write_private(path, text)
    return [path for path, _ in outputs]


def resolve(folder: Path) -> tuple[Path, Path | None]:
    """A case folder (with raw/) or a capture folder -> (raw dir, default output)."""
    if (folder / "raw").is_dir():
        return folder / "raw", folder / REPORT_DIR / MARKDOWN_NAME
    return folder, None


def markdown_report(raw_dir: Path, pack: str) -> tuple[str, int]:
    """The report text and the number of lines appopsy couldn't parse."""
    analysis = analyse(raw_dir, pack)
    return analysis.markdown(), analysis.warnings


def write_private(path: Path, text: str) -> None:
    """Reports hold personal data: 0700 folder, 0600 file, like the case folder."""
    path.parent.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    path.chmod(0o600)  # an existing file keeps its old mode through os.open
