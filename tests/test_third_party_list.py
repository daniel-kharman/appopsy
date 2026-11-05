"""Local-only check against your own app list (synthetic names here)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from appopsy import cli
from appopsy.redact import scan_tree
from appopsy.redact_packages import check_outside_repo, load_third_party_list

runner = CliRunner()

MY_APPS = """\
package:com.example.bank  installer=com.android.vending
package:com.whatsapp  installer=com.android.vending
org.example.diary
# comment
"""


@pytest.fixture
def lists(tmp_path: Path) -> tuple[Path, Path]:
    """(app list outside any repo, a directory of files to check)."""
    home = tmp_path / "home"
    home.mkdir()
    my_apps = home / "my-apps.txt"
    my_apps.write_text(MY_APPS)
    docs = tmp_path / "work" / "docs"
    docs.mkdir(parents=True)
    return my_apps, docs


def test_load_list_accepts_pm_output_and_bare_names(lists: tuple[Path, Path]) -> None:
    assert load_third_party_list(lists[0]) == {
        "com.example.bank",
        "com.whatsapp",
        "org.example.diary",
    }


def test_mentions_anywhere_are_found(lists: tuple[Path, Path]) -> None:
    my_apps, docs = lists
    (docs / "notes.md").write_text(
        "A permission like `com.example.bank.permission.C2D_MESSAGE` leaks the app.\n"
        "So does a sentence about org.example.diary.\n"
        "com.whatsapp is allowlisted, so naming it is fine.\n"
        "com.example.bankruptcy is a different name.\n"
    )
    found = {
        (f.line, f.value) for _, f in scan_tree([docs], third_party=load_third_party_list(my_apps))
    }
    assert found == {(1, "com.example.bank"), (2, "org.example.diary")}
    assert scan_tree([docs]) == []  # without the list (as in CI) prose isn't checked


def test_cli_check_masks_names(lists: tuple[Path, Path]) -> None:
    my_apps, docs = lists
    (docs / "x.md").write_text("see com.example.bank.provider\n")
    result = runner.invoke(
        cli.app, ["redact-fixture", "--check", "--third-party-list", str(my_apps), str(docs)]
    )
    assert result.exit_code == 1
    assert "my_app" in result.output
    assert "com.example.bank" not in result.output
    (docs / "x.md").write_text("nothing personal\n")
    clean = runner.invoke(
        cli.app, ["redact-fixture", "--check", "--third-party-list", str(my_apps), str(docs)]
    )
    assert clean.exit_code == 0
    assert "any of your 3 listed apps" in " ".join(clean.output.split())


def test_list_inside_a_repo_is_refused(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    inside = repo / "my-apps.txt"
    inside.write_text(MY_APPS)
    with pytest.raises(ValueError, match="outside the repository"):
        check_outside_repo(inside)
    result = runner.invoke(
        cli.app, ["redact-fixture", "--check", "--third-party-list", str(inside), str(repo)]
    )
    assert result.exit_code == 2


def test_redaction_uses_the_list_as_knowledge(lists: tuple[Path, Path], tmp_path: Path) -> None:
    my_apps, _ = lists
    src = tmp_path / "raw"
    src.mkdir()
    # No pm list in the input, so only the list tells the redactor this is a third-party app.
    (src / "dumpsys.txt").write_text(
        "    shareTarget=com.example.bank.ShareActivity\n    keep=me\n"
    )
    out = tmp_path / "out"
    result = runner.invoke(
        cli.app, ["redact-fixture", str(src), "--out", str(out), "--third-party-list", str(my_apps)]
    )
    assert result.exit_code == 0, result.output
    assert (out / "dumpsys.txt").read_text() == "    keep=me\n"


def test_bad_list_line(tmp_path: Path) -> None:
    bad = tmp_path / "bad.txt"
    bad.write_text("not a package!\n")
    with pytest.raises(ValueError, match="Bad third-party list line"):
        load_third_party_list(bad)


def test_apps_only_ignores_synthetic_identifiers(lists: tuple[Path, Path]) -> None:
    my_apps, docs = lists
    (docs / "test_x.py").write_text('SERIAL = "serial=ZZ123ABC456"  # synthetic, on purpose\n')
    argv = ["redact-fixture", "--check", "--third-party-list", str(my_apps), str(docs)]
    assert runner.invoke(cli.app, argv).exit_code == 1  # full scan flags the serial
    assert runner.invoke(cli.app, [*argv, "--apps-only"]).exit_code == 0
    (docs / "test_x.py").write_text("PKG = 'com.example.bank'\n")
    assert runner.invoke(cli.app, [*argv, "--apps-only"]).exit_code == 1
    assert (
        runner.invoke(cli.app, ["redact-fixture", "--check", "--apps-only", str(docs)]).exit_code
        == 2
    )


def test_directory_walk_skips_hidden_dirs_and_caches(lists: tuple[Path, Path]) -> None:
    my_apps, docs = lists
    for d in (".venv/lib", ".git", "__pycache__"):
        (docs / d).mkdir(parents=True)
        (docs / d / "x.txt").write_text("com.example.bank\n")
    assert scan_tree([docs], third_party=load_third_party_list(my_apps)) == []


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_apps_only_skips_ignored_paths_but_not_untracked_ones(lists: tuple[Path, Path]) -> None:
    """In a git work tree only files git tracks or could commit are scanned: an
    ignored cases/ folder with a listed app passes, an untracked file doesn't."""
    my_apps, _ = lists
    repo = my_apps.parent / "repo"
    repo.mkdir()
    git = shutil.which("git")
    assert git is not None
    subprocess.run([git, "init", "-q", str(repo)], check=True)
    (repo / ".gitignore").write_text("cases/\n")
    (repo / "README.md").write_text("Nothing personal here.\n")
    case = repo / "cases" / "20300101T000000Z-pixel" / "raw"
    case.mkdir(parents=True)
    (case / "pm-list-packages-3p.txt").write_text("package:com.example.bank\n")
    argv = ["redact-fixture", "--check", "--apps-only", "--third-party-list", str(my_apps)]
    result = runner.invoke(cli.app, [*argv, str(repo)])
    assert result.exit_code == 0, result.output  # ignored: the owner's own case data
    (repo / "notes.txt").write_text("remember com.example.bank\n")  # untracked, not ignored
    assert runner.invoke(cli.app, [*argv, str(repo)]).exit_code == 1
