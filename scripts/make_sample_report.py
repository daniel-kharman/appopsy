#!/usr/bin/env python3
"""Regenerate docs/sample-report.{md,html}: capture-5, redacted.

    uv run python scripts/make_sample_report.py

Uses a fixed alias key so the committed sample is reproducible (and its test can
compare it exactly). Real reports never do this: `appopsy report --redact` makes a
fresh random key every time, so two shared reports can't be linked.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from appopsy.report.run import analyse

ROOT = Path(__file__).resolve().parent.parent
CAPTURE = ROOT / "tests" / "fixtures" / "17-google" / "capture-5"
KEY = hashlib.sha256(b"appopsy sample report").digest()


def render() -> tuple[str, str]:
    rendered = analyse(CAPTURE, "privacy").render(redact=True, key=KEY)
    return rendered.markdown, rendered.html


def main() -> None:
    markdown, html = render()
    (ROOT / "docs" / "sample-report.md").write_text(markdown, encoding="utf-8")
    (ROOT / "docs" / "sample-report.html").write_text(html, encoding="utf-8")
    print("wrote docs/sample-report.md and docs/sample-report.html")


if __name__ == "__main__":
    main()
