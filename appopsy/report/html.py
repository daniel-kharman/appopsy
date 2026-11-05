"""Render a report as one self-contained HTML file (``templates/report.html.j2``).

Same view model as the Markdown report. Inline CSS only: no scripts, fonts or
anything else loaded from the network, so opening a report contacts nobody.
Everything is autoescaped; rule text (trusted, from the repo) additionally gets
`code` spans turned into <code>.
"""

from __future__ import annotations

import re

from jinja2 import Environment, PackageLoader, StrictUndefined
from markupsafe import Markup, escape

from appopsy.report.build import Report

_CODE = re.compile(r"`([^`]+)`")


def rule_text(text: object) -> Markup:
    """Rule-spec prose: escaped, with `code` spans as <code>."""
    escaped = str(escape(str(text)))
    return Markup(_CODE.sub(r"<code>\1</code>", escaped))  # noqa: S704 - escaped above


def _env() -> Environment:
    env = Environment(
        loader=PackageLoader("appopsy.report", "templates"),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=StrictUndefined,
    )
    env.filters["rule"] = rule_text
    return env


def render_html(report: Report) -> str:
    return _env().get_template("report.html.j2").render(r=report)
