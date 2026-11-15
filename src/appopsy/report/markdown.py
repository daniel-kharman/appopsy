"""Render a report as Markdown (Jinja2 template in ``templates/report.md.j2``).

Text from the device (package, worker and alarm names) is untrusted: it goes
through ``code`` (an inline code span) or ``cell`` (a table cell), never raw.
"""

from __future__ import annotations

import re

from jinja2 import Environment, PackageLoader, StrictUndefined

from appopsy.report.build import Report

# Text is always inline (newlines become spaces), so `#`, `>` and list markers can't
# start a block, and with `<` escaped a lone `>` can't close a tag: it stays as is,
# so "Settings > Apps" reads cleanly. Underscores only need escaping at a word edge
# (GFM ignores intraword ones), which keeps names like FINE_LOCATION readable.
_PROSE_SPECIAL = re.compile(r"[\\`*\[\]<|]|(?<!\w)_|_(?!\w)")


def md(text: object) -> str:
    """Escape prose so nothing in it becomes Markdown or HTML."""
    return _PROSE_SPECIAL.sub(lambda m: "\\" + m.group(0), str(text).replace("\n", " "))


def code(text: object) -> str:
    """An inline code span that survives backticks in the value."""
    value = str(text).replace("\n", " ")
    longest = max((len(m) for m in re.findall(r"`+", value)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if value.startswith("`") or value.endswith("`") or longest else ""
    return f"{fence}{pad}{value}{pad}{fence}"


def cell(text: object) -> str:
    """A table cell: escaped like prose (pipes would end the cell)."""
    return md(text) or " "


def _env() -> Environment:
    env = Environment(
        loader=PackageLoader("appopsy.report", "templates"),
        # Markdown, not HTML: device text is escaped by the md/code/cell filters.
        autoescape=False,  # noqa: S701
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        undefined=StrictUndefined,
    )
    env.filters.update(md=md, code=code, cell=cell)
    return env


def render_markdown(report: Report) -> str:
    text = _env().get_template("report.md.j2").render(r=report)
    text = re.sub(r"\n{3,}", "\n\n", text).rstrip("\n") + "\n"
    return resolve_anchors(text)


_HEADING = re.compile(r"^(#{1,6}) (.*)$")
_ANCHOR = re.compile(r" @@anchor:([\w-]+)@@$")
_REF = re.compile(r"#@@ref:([\w-]+)@@")


def github_slug(title: str) -> str:
    """The anchor GitHub gives a heading: lowercase, punctuation dropped (letters,
    digits, `_` and `-` kept), spaces to hyphens."""
    return re.sub(r"[^\w\- ]", "", title.lower()).replace(" ", "-")


def resolve_anchors(text: str) -> str:
    """Strip " @@anchor:KEY@@" heading markers and point "#@@ref:KEY@@" links at the
    slug GitHub gives that heading, counting repeats ("-1", "-2") as GitHub does."""
    slugs: dict[str, str] = {}
    seen: dict[str, int] = {}
    lines = []
    for line in text.splitlines():
        if m := _HEADING.match(line):
            title, key = m[2], None
            if a := _ANCHOR.search(title):
                title, key = title[: a.start()], a[1]
                line = f"{m[1]} {title}"
            slug = github_slug(title)
            n = seen.get(slug, 0)
            seen[slug] = n + 1
            if n:
                slug = f"{slug}-{n}"
            if key:
                slugs[key] = slug
        lines.append(line)
    resolved = "\n".join(lines) + "\n"
    return _REF.sub(lambda m: "#" + slugs.get(m[1], ""), resolved)
