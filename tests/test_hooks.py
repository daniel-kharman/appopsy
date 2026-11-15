"""The checked-in git hooks (.githooks/), run for real against a throwaway repo."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HOOKS = ROOT / ".githooks"
ZERO = "0" * 40
GIT = shutil.which("git")
# The venv running these tests (the repo's .venv, also when the pre-commit hook
# runs pytest in an exported copy of the staged tree).
VENV = Path(sys.prefix)

pytestmark = pytest.mark.skipif(
    GIT is None or not (VENV / "bin" / "appopsy").exists(),
    reason="needs git and the project's virtualenv",
)


def test_hooks_exist_and_are_executable() -> None:
    for name in ("pre-commit", "pre-push"):
        hook = HOOKS / name
        assert hook.is_file() and os.access(hook, os.X_OK), name
    pre_commit = (HOOKS / "pre-commit").read_text()
    assert "checkout-index" in pre_commit  # checks the staged tree, not the working tree
    for tool in ('ruff" check', 'ruff" format --check', "mypy", "pytest"):
        assert tool in pre_commit, tool


def git(repo: Path, *args: str) -> str:
    assert GIT is not None
    return subprocess.run(
        [GIT, "-c", "user.name=t", "-c", "user.email=t@example.test", *args],
        cwd=repo, check=True, capture_output=True, text=True,
    ).stdout.strip()  # fmt: skip


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    (r / ".venv").symlink_to(VENV)  # the hook uses <repo>/.venv
    (r / ".gitignore").write_text(".venv\n")
    (r / "README.md").write_text("clean\n")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "clean start")
    # A real (empty) remote: the hook asks it which commits it already has.
    origin = tmp_path / "origin.git"
    git(tmp_path, "init", "-q", "--bare", str(origin))
    git(r, "remote", "add", "origin", str(origin))
    git(r, "config", "push.useBitmaps", "false")  # setup step (CLAUDE.md)
    return r


def push_hook(
    repo: Path,
    home: Path,
    app_list: Path | None,
    extra_env: dict[str, str] | None = None,
    url: str | None = None,
) -> subprocess.CompletedProcess[str]:
    head = git(repo, "rev-parse", "HEAD")
    env = {**os.environ, "HOME": str(home), **(extra_env or {})}
    env.pop("APPOPSY_THIRD_PARTY_LIST", None)
    if app_list is not None:
        env["APPOPSY_THIRD_PARTY_LIST"] = str(app_list)
    assert GIT is not None
    found = subprocess.run(
        [GIT, "remote", "get-url", "origin"], cwd=repo, capture_output=True, text=True
    )
    url = url or found.stdout.strip() or "url"
    return subprocess.run(
        [str(HOOKS / "pre-push"), "origin", url],
        cwd=repo, input=f"refs/heads/main {head} refs/heads/main {ZERO}\n",
        env=env, capture_output=True, text=True,
    )  # fmt: skip


@pytest.fixture
def app_list(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    lst = home / "my-apps.txt"
    lst.write_text("package:com.example.bank  installer=com.android.vending\n")
    return lst


def test_pre_push_passes_clean_history(repo: Path, app_list: Path) -> None:
    result = push_hook(repo, app_list.parent, app_list)
    assert result.returncode == 0, result.stderr
    assert "passed for every commit" in result.stderr


def test_pre_push_blocks_an_app_anywhere_in_the_pushed_history(repo: Path, app_list: Path) -> None:
    (repo / "notes.md").write_text("we saw com.example.bank.permission.SYNC\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "add notes")
    (repo / "notes.md").write_text("cleaned up\n")  # removed again at the tip...
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "clean notes")
    result = push_hook(repo, app_list.parent, app_list)
    assert result.returncode == 1  # ...but the earlier commit is still being pushed
    assert "one of your apps is named in the tree" in result.stderr
    assert "com.example.bank" not in result.stderr  # never printed


def test_pre_push_checks_commit_messages(repo: Path, app_list: Path) -> None:
    (repo / "x.txt").write_text("x\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "fix parsing for com.example.bank")
    result = push_hook(repo, app_list.parent, app_list)
    assert result.returncode == 1
    assert "named in the commit message" in result.stderr


def test_pre_push_ignores_forged_remote_tracking_refs(repo: Path, app_list: Path) -> None:
    """A sandboxed process can write refs/remotes/*. A forged origin/main pointing at
    the new commit must not make the hook treat it as already pushed: the hook asks
    the remote (here an empty one) what it has."""
    (repo / "notes.md").write_text("we saw com.example.bank\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "add notes")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")  # forged
    result = push_hook(repo, app_list.parent, app_list)
    assert result.returncode == 1, result.stderr
    assert "one of your apps is named in the tree" in result.stderr


def test_pre_push_skips_only_what_the_remote_really_has(repo: Path, app_list: Path) -> None:
    """Commits the remote already has are public, so they aren't checked again; new
    commits on top still are."""
    (repo / "x.txt").write_text("x\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "already public: com.example.bank")
    git(repo, "push", "-q", "--no-verify", "origin", "main")  # the remote has it now
    (repo / "y.txt").write_text("y\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "new and clean")
    result = push_hook(repo, app_list.parent, app_list)
    assert result.returncode == 0, result.stderr
    (repo / "z.txt").write_text("z\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "new: com.example.bank")
    result = push_hook(repo, app_list.parent, app_list)
    assert result.returncode == 1
    assert "named in the commit message" in result.stderr


def test_pre_push_refuses_when_the_remote_cant_be_asked(
    repo: Path, app_list: Path, tmp_path: Path
) -> None:
    git(repo, "remote", "set-url", "origin", str(tmp_path / "no-such-remote.git"))
    result = push_hook(repo, app_list.parent, app_list)
    assert result.returncode == 1
    assert "couldn't ask 'origin' which commits it already has" in result.stderr
    assert "passed for every commit" not in result.stderr


def test_pre_push_refuses_when_asking_the_remote_times_out(repo: Path, app_list: Path) -> None:
    # git runs this instead of git-upload-pack for the local remote: it never answers
    # in time.
    git(repo, "config", "remote.origin.uploadpack", "sleep 5; false")
    result = push_hook(  # by name, so git applies the remote's uploadpack setting
        repo, app_list.parent, app_list, extra_env={"APPOPSY_LS_REMOTE_TIMEOUT": "1"},
        url="origin",
    )  # fmt: skip
    assert result.returncode == 1
    assert "timed out" in result.stderr


def test_pre_push_tolerates_remote_commits_it_doesnt_have(
    repo: Path, app_list: Path, tmp_path: Path
) -> None:
    """GitHub lists pull-request refs whose commits aren't local: they're left out of
    the known set, not a reason to stop (silently) under set -e."""
    other = tmp_path / "other-clone"
    git(tmp_path, "clone", "-q", git(repo, "remote", "get-url", "origin"), str(other))
    (other / "theirs.txt").write_text("x\n")
    git(other, "add", "-A")
    git(other, "commit", "-q", "-m", "someone else's commit")
    git(other, "push", "-q", "--no-verify", "origin", "HEAD:refs/pull/1/head")
    result = push_hook(repo, app_list.parent, app_list)
    assert result.returncode == 0, result.stderr
    assert "passed for every commit" in result.stderr


def test_pre_push_ignores_grafts(repo: Path, app_list: Path) -> None:
    """A planted graft can make the remote's commit look like a descendant of the new
    one, so a grafted walk finds nothing new; the hook walks the real parents."""
    git(repo, "push", "-q", "--no-verify", "origin", "main")
    pushed = git(repo, "rev-parse", "HEAD")
    (repo / "notes.md").write_text("we saw com.example.bank\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "add notes")
    new = git(repo, "rev-parse", "HEAD")
    (repo / ".git" / "info").mkdir(exist_ok=True)
    (repo / ".git" / "info" / "grafts").write_text(f"{pushed} {new}\n")
    result = push_hook(repo, app_list.parent, app_list)
    assert result.returncode == 1, result.stderr
    assert "one of your apps is named in the tree" in result.stderr


def test_pre_push_refuses_a_shallow_clone(repo: Path, app_list: Path) -> None:
    (repo / ".git" / "shallow").write_text(git(repo, "rev-parse", "HEAD") + "\n")
    result = push_hook(repo, app_list.parent, app_list)
    assert result.returncode == 1
    assert "shallow" in result.stderr


def test_pre_push_requires_push_bitmaps_off(repo: Path, app_list: Path) -> None:
    """With bitmaps, git push can send commits the hook's walk didn't see."""
    git(repo, "config", "--unset", "push.useBitmaps")
    result = push_hook(repo, app_list.parent, app_list)
    assert result.returncode == 1
    assert "push.useBitmaps false" in result.stderr


def test_pre_push_fails_closed_without_the_list(repo: Path, tmp_path: Path) -> None:
    empty_home = tmp_path / "empty-home"
    empty_home.mkdir()
    result = push_hook(repo, empty_home, None)
    assert result.returncode == 1
    assert "no app list" in result.stderr


@pytest.fixture
def broken_repo(tmp_path: Path) -> Path:
    """A repo whose .venv exists but can't run: every tool points at an interpreter
    that isn't there (what a moved or half-deleted virtualenv looks like)."""
    r = tmp_path / "broken"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    bin_dir = r / ".venv" / "bin"
    bin_dir.mkdir(parents=True)
    for tool in ("python", "pytest", "ruff", "mypy", "appopsy"):
        script = bin_dir / tool
        script.write_text("#!/nonexistent/interpreter/python3\nprint('never runs')\n")
        script.chmod(0o755)
    (r / ".gitignore").write_text(".venv\n")
    (r / "README.md").write_text("clean\n")
    git(r, "add", "-A")
    git(r, "commit", "-q", "--no-verify", "-m", "clean start")
    return r


def shell_error(stderr: str) -> bool:
    """The shell's own error for the unrunnable tool, as each shell words it: macOS sh
    says "bad interpreter: No such file or directory", dash (Linux) "<path>: not found"."""
    return ".venv/bin/" in stderr and any(
        s in stderr for s in ("bad interpreter", "No such file or directory", "not found")
    )


def test_pre_commit_reports_a_broken_environment(broken_repo: Path) -> None:
    result = subprocess.run(
        [str(HOOKS / "pre-commit")], cwd=broken_repo, capture_output=True, text=True
    )
    assert result.returncode == 1
    assert "environment" in result.stderr and "broken" in result.stderr
    assert shell_error(result.stderr)  # the real error is shown
    assert "check failed" not in result.stderr


def test_pre_push_reports_a_broken_environment(broken_repo: Path, app_list: Path) -> None:
    result = push_hook(broken_repo, app_list.parent, app_list)
    assert result.returncode == 1
    assert "environment" in result.stderr and "broken" in result.stderr
    assert shell_error(result.stderr)
    # Not mistaken for a finding.
    assert "named" not in result.stderr and "check failed" not in result.stderr


@pytest.mark.parametrize(("verify_exit", "push_ok"), [(0, True), (1, False), (2, False)])
def test_pre_push_verifies_a_changed_names_file(
    repo: Path, app_list: Path, verify_exit: int, push_ok: bool
) -> None:
    """A commit that changes the Wikidata names file must pass --verify (a stub here,
    so the test needs no network); exit 2 (Wikidata unreachable) also refuses."""
    names = repo / "appopsy" / "report" / "app_names.tsv"
    names.parent.mkdir(parents=True)
    names.write_text("# not the real file\n")
    script = repo / "scripts" / "update_app_names.py"
    script.parent.mkdir()
    script.write_text(f"import sys\nprint('stub verify')\nsys.exit({verify_exit})\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--no-verify", "-m", "update names")
    result = push_hook(repo, app_list.parent, app_list)
    assert (result.returncode == 0) is push_ok, result.stderr
    if not push_ok:
        assert "didn't verify against Wikidata" in result.stderr and "stub verify" in result.stderr


def test_pre_push_runs_the_working_tree_verify_script_not_the_pushed_one(
    repo: Path, app_list: Path
) -> None:
    """A commit can be written from inside the Claude Code sandbox, and this hook runs
    outside it, so it never runs code taken from the pushed commit."""
    names = repo / "appopsy" / "report" / "app_names.tsv"
    names.parent.mkdir(parents=True)
    names.write_text("# not the real file\n")
    script = repo / "scripts" / "update_app_names.py"
    script.parent.mkdir()
    script.write_text("import sys\nprint('pushed copy ran')\nsys.exit(1)\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--no-verify", "-m", "update names")
    script.write_text("import sys\nprint('working tree copy')\nsys.exit(0)\n")
    result = push_hook(repo, app_list.parent, app_list)
    assert result.returncode == 0, result.stderr
    assert "pushed copy ran" not in result.stderr + result.stdout


def test_pre_push_skips_verify_when_the_names_file_is_unchanged(repo: Path, app_list: Path) -> None:
    script = repo / "scripts" / "update_app_names.py"
    script.parent.mkdir()
    script.write_text("import sys\nsys.exit(1)\n")  # would fail if it ran
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--no-verify", "-m", "a script, no names file")
    assert push_hook(repo, app_list.parent, app_list).returncode == 0
