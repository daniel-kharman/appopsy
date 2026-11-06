"""The Wikidata names file: format, untrusted labels, the narrow exemption from the
"your apps" check, and display-only use (redaction is unchanged)."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from appopsy.redact import scan_tree
from appopsy.report import app_names
from appopsy.report.app_names import (
    MAX_LABEL,
    MIN_ROWS,
    PATH_IN_REPO,
    QUERY,
    bundled_text,
    label_problem,
    parse,
    validate,
)
from appopsy.report.build import app_label, build_report, known_apps
from appopsy.report.markdown import render_markdown
from appopsy.report.redaction import plan
from appopsy.rules.case import CaseData
from appopsy.rules.engine import Finding, load_rules

ROOT = Path(__file__).resolve().parent.parent
CAPTURE = ROOT / "tests" / "fixtures" / "17-google" / "capture-5"
HEADER = (
    "# Friendly names for widely used Android apps.\n"
    '# Source: Wikidata (https://www.wikidata.org), property P3418 "Google Play Store app ID".\n'
    "# Licence: CC0 1.0 (public domain), https://creativecommons.org/publicdomain/zero/1.0/\n"
    f"# Query: {QUERY}\n"
)


def synthetic(extra: dict[str, str] | None = None, n: int = MIN_ROWS) -> str:
    """A valid file of synthetic rows (com.example.*), plus ``extra`` package -> name."""
    rows = {f"com.example.app{i:05d}": f"Example {i}" for i in range(n)} | (extra or {})
    body = "".join(f"{p}\t{name}\tQ{i + 1}\n" for i, (p, name) in enumerate(sorted(rows.items())))
    return HEADER + body


def load_generator():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(
        "update_app_names", ROOT / "scripts" / "update_app_names.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- the bundled file ---------------------------------------------------------------


def test_bundled_file_validates() -> None:
    text = bundled_text()
    header, rows, problems = parse(text)
    assert problems == []
    assert len(rows) >= MIN_ROWS
    assert f"# Query: {QUERY}" in header  # the generator's exact query
    assert any(re.match(r"# Retrieved: \d{4}-\d\d-\d\d\. Rows: \d+", h) for h in header)
    assert (ROOT / PATH_IN_REPO).read_text() == text


def test_bundled_names_for_the_fixture_apps() -> None:
    names = app_names.names()
    assert names["com.whatsapp"] == "WhatsApp"  # "...app" inside a word is kept
    assert names["com.facebook.katana"] == "Facebook"  # a trailing " app" is removed


# --- untrusted labels ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "problem"),
    [
        ("", "empty"),
        ("x" * (MAX_LABEL + 1), "longer than"),
        ("Bad\x00name", "control"),
        ("Bad​name", "control"),  # zero-width space isn't printable
        ("Tab\tname", "control"),
        (" Lead", "whitespace"),
        ("Two  spaces", "whitespace"),
        ("<script>alert(1)</script>", "markup"),
        ("[click](https://example.com)", "markup"),
        ("`code`", "markup"),
        ("**bold**", "markup"),
        ("a|b", "markup"),
        ("https://example.com", "link"),
        ("www.example.com", "link"),
    ],
)
def test_untrusted_labels_are_rejected(label: str, problem: str) -> None:
    why = label_problem(label)
    assert why is not None and problem in why


@pytest.mark.parametrize(
    "label", ["Example", "Ex & Co.", "Plus+ App: Notes", "Café 2", "x" * MAX_LABEL]
)
def test_plain_names_are_accepted(label: str) -> None:
    assert label_problem(label) is None


def test_format_problems_are_reported() -> None:
    ok = synthetic()
    assert validate(ok) == []
    assert any("markup" in p for p in validate(synthetic({"com.example.zz": "<b>x</b>"})))
    assert any("too" in p or "only" in p for p in validate(synthetic(n=10)))
    assert "rows not sorted by package" in validate(
        HEADER + "com.example.b\tB\tQ2\ncom.example.a\tA\tQ1\n"
    )
    assert any(
        "query" in p.lower() for p in validate(ok.replace(f"# Query: {QUERY}", "# Query: x"))
    )
    assert any("three" in p for p in validate(ok + "com.example.zzz\tno id\n"))
    assert any("Wikidata ID" in p for p in validate(ok + "com.example.zzz\tName\tX1\n"))


# --- the exemption ------------------------------------------------------------------


@pytest.fixture
def tree(tmp_path: Path) -> tuple[Path, set[str]]:
    root = tmp_path / "tree"
    (root / "appopsy" / "report").mkdir(parents=True)
    (root / "README.md").write_text("Nothing personal.\n")
    return root, {"com.example.bank"}


def my_app_findings(root: Path, mine: set[str]) -> list[str]:
    return [
        str(p.relative_to(root))
        for p, f in scan_tree([root], third_party=mine)
        if f.category == "my_app"
    ]


def test_rows_of_a_valid_names_file_are_exempt(tree: tuple[Path, set[str]]) -> None:
    root, mine = tree
    (root / PATH_IN_REPO).write_text(synthetic({"com.example.bank": "Example Bank"}))
    assert my_app_findings(root, mine) == []


def test_exemption_fails_closed(tree: tuple[Path, set[str]]) -> None:
    root, mine = tree
    names = root / PATH_IN_REPO
    # An invalid file (one bad row) is scanned whole.
    names.write_text(synthetic({"com.example.bank": "Example Bank"}) + "garbage line\n")
    assert my_app_findings(root, mine) == [PATH_IN_REPO]
    # A short, hand-picked list isn't the public set: not exempt.
    names.write_text(synthetic({"com.example.bank": "Example Bank"}, n=10))
    assert my_app_findings(root, mine) == [PATH_IN_REPO]
    # The header is always scanned.
    names.write_text(synthetic().replace("# Friendly", "# com.example.bank Friendly"))
    assert my_app_findings(root, mine) == [PATH_IN_REPO]


def test_exemption_covers_only_that_path(tree: tuple[Path, set[str]]) -> None:
    root, mine = tree
    text = synthetic({"com.example.bank": "Example Bank"})
    (root / "docs").mkdir()
    (root / "docs" / "app_names.tsv").write_text(text)
    assert my_app_findings(root, mine) == ["docs/app_names.tsv"]


# --- display only -------------------------------------------------------------------


def test_names_are_shown_but_redaction_still_aliases() -> None:
    """A widely used app from the names file is named in the owner's report but still
    aliased in a redacted copy: which popular apps you have is personal."""
    package, name = next(
        (p, n) for p, n in sorted(app_names.names().items()) if p not in known_apps()
    )
    assert app_label(package) == f"{name} ({package})"
    case = CaseData(CAPTURE)
    (spec,) = [s for s in load_rules() if s.id == "over-privileged-app"]
    f = Finding(
        rule_id=spec.id, pack="privacy", severity="info", title=spec.title, package=package,
        summary=f"{package} isn't allowed any of the 9 kinds of sensitive access appopsy checks.",
        facts={"rank": 1, "of": 1, "checked": 9, "count": 0, "categories": {}, "allowed": {}},
    )  # fmt: skip
    assert f"{name} ({package})" in render_markdown(build_report(case, [spec], [f]))
    redaction = plan(case, [f], public=set(known_apps()))
    assert package in redaction.aliases
    shared = render_markdown(build_report(case, [spec], [f], redaction=redaction))
    assert package not in shared and redaction.aliases[package] in shared


def test_report_credits_wikidata() -> None:
    case = CaseData(CAPTURE)
    text = render_markdown(build_report(case, load_rules(packs=("privacy",)), []))
    assert "App names for widely used apps come from [Wikidata](https://www.wikidata.org)" in text
    assert "(CC0, public domain)" in text


# --- the generator --------------------------------------------------------------------


def test_generator_rules() -> None:
    gen = load_generator()
    assert gen.QUERY == QUERY
    assert [gen.clean(x) for x in ("Example app", "Example Android app", "Example (app)", "Snapp")] == [
        "Example", "Example", "Example", "Snapp",
    ]  # fmt: skip
    item = "http://www.wikidata.org/entity/"
    bindings = [
        {"item": item + "Q20", "id": "com.example.a", "en": "Alpha", "links": "3"},
        {"item": item + "Q10", "id": "com.example.a", "en": "Alpha (company)", "links": "3"},
        {
            "item": item + "Q30",
            "id": "com.example.a",
            "en": "Alpha app",
            "links": "9",
        },  # most articles
        {"item": item + "Q40", "id": "com.example.b", "mul": "Beta"},  # no English label
        {"item": item + "Q50", "id": "com.example.c", "en": "<b>Gamma</b>"},  # markup: dropped
        {"item": item + "Q60", "id": "not a package", "en": "Delta"},  # dropped
    ]
    rows, pairs, dropped = gen.generate(bindings)
    assert rows == {"com.example.a": ("Alpha", "Q30"), "com.example.b": ("Beta", "Q40")}
    assert dropped == 2 and ("com.example.a", "Q10") in pairs
    # Ties go to the lowest item number.
    rows, _, _ = gen.generate(bindings[:2])
    assert rows["com.example.a"][1] == "Q10"
