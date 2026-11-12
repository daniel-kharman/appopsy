"""The checked-in Claude Code configuration (.claude/): the command guard hook, the
permissions in settings.json, and the read-only reviewer agents."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CLAUDE = ROOT / ".claude"
HOOK = CLAUDE / "hooks" / "command_guard.py"
# The venv running these tests (the repo's .venv, also when the pre-commit hook
# runs pytest in an exported copy of the staged tree); the guard finds
# `appopsy` through CLAUDE_PROJECT_DIR/.venv.
VENV = Path(sys.prefix)
HAS_APPOPSY = (VENV / "bin" / "appopsy").exists()


def run_hook(
    command: str, *, reviewer: bool = False, env: dict[str, str] | None = None
) -> str | None:
    """The hook's permission decision for a Bash command (None: no objection)."""
    event = {"tool_name": "Bash", "tool_input": {"command": command}}
    args = [sys.executable, "-I", str(HOOK), *(["--reviewer"] if reviewer else [])]
    out = subprocess.run(
        args,
        input=json.dumps(event),
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "CLAUDE_PROJECT_DIR": str(VENV.parent), **(env or {})},
    ).stdout
    if not out.strip():
        return None
    decision: str = json.loads(out)["hookSpecificOutput"]["permissionDecision"]
    return decision


ROUTINE = [
    "gh api repos/o/r",
    "gh api repos/o/r/rulesets --jq '.[].id'",
    "gh api -X GET repos/o/r/issues -f state=open",
    "gh api --method=get repos/o/r",
    "gh api -i repos/o/r/vulnerability-alerts 2>&1 | head -1",
    "gh api repos/o/r && gh api repos/o/r/rulesets",
    "gh api --paginate repos/o/r/pulls/1/files -q '.[].filename'",
    "gh api -H 'Accept: application/vnd.github.raw' repos/o/r/contents/x",
    "gh pr view 12",
    "uv run pytest -q",
    "uv run pytest -q tests/test_x.py -p no:cacheprovider",
    "uv run ruff check .",
    "uv run ruff format --check .",
    "uv run mypy",
    "git status -sb",
    "git diff --name-only origin/main...HEAD",
    "git log -1 --format=%B",
    "git add -A",
    "git add .claude docs/x.md",
    "git commit -q -m 'Fix the thing'",
    "git commit -q -F - <<'EOF'\nmessage\nEOF",
    "git switch -c fix-foo origin/main",
    "git checkout -b feature-x",
    "echo hi",
]

NOT_ROUTINE = [
    # gh api: explicit methods, fields, bodies
    "gh api -X POST repos/o/r/labels -f name=x",
    "gh api --method PATCH repos/o/r -F private=true",
    "gh api --method=DELETE repos/o/r/git/refs/heads/x",
    "gh api -XPUT repos/o/r/topics",
    "gh api repos/o/r/labels -f name=x",
    "gh api repos/o/r/labels -Fname=x",
    "gh api repos/o/r/labels --raw-field=name=x",
    "gh api repos/o/r/rulesets --input rules.json",
    "gh api graphql -f query='mutation { x }'",
    "gh api graphql -X GET -f query='mutation { x }'",
    "gh api -H 'X-HTTP-Method-Override: DELETE' repos/o/r",
    # gh api: combined short flags and value flags hiding a fake GET (review finding)
    "gh api -iXDELETE repos/o/r",
    "gh api -iX POST repos/o/r/labels",
    "gh api -if name=x repos/o/r/labels",
    "gh api -iFname=x repos/o/r/labels",
    "gh api -X DELETE repos/o/r -t -XGET",
    "gh api -X POST repos/o/r/labels -f name=x -t -XGET",
    "gh api --method PUT repos/o/r/topics --input=f.json -t --method=GET",
    "gh api -X DELETE repos/o/r -q -XGET",
    "gh api repos/o/r extra-positional",
    # gh api: hidden in quotes or other commands (review finding)
    'gh "api" -X POST repos/o/r/labels',
    '"gh" api -X POST repos/o/r/labels',
    'gh ap""i -X POST repos/o/r',
    "gh api repos/o/r; gh api -X DELETE repos/o/r",
    "sh -c 'gh api -X DELETE repos/o/r'",
    "echo $(gh api -X POST repos/o/r/forks)",
    "echo `gh api -X POST repos/o/r/forks`",
    "gh api repos/o/r 'unterminated",
    "gh api -X",
    "timeout 30 gh api -X DELETE repos/o/r",
    # gh pr create elsewhere
    "gh pr create -R other/repo --title t --body b",
    "gh pr create --repo=other/repo --title t --body b",
    "gh pr create --title t --body-file -",
    # git: skipping hooks (review finding)
    "git commit -n -m x",
    "git commit -nm x",
    "git commit -am x -n",
    "git commit --no-verify -m x",
    "git commit --no-verif -m x",
    "git -c core.hooksPath=/dev/null commit -m x",
    "git push --no-verif origin x",
    # git: writing files, staging ignored files, discarding work (review finding)
    "git diff --output=.githooks/pre-push",
    "git log --output .githooks/pre-push",
    "git add -f cases/",
    "git add --force .claude/settings.local.json",
    "git add -Af .",
    "git switch -c x --discard-changes",
    "git switch -c x -f",
    "git checkout -b x -f",
    "git checkout --force -b x",
    # pytest, ruff, mypy: writes, deletes, uploads (review finding)
    "uv run pytest --basetemp=/some/dir",
    "uv run pytest --pastebin=all",
    "uv run pytest --junitxml=out.xml",
    "uv run pytest -o cache_dir=/elsewhere",
    "uv run ruff check --output-file out.txt .",
    "uv run ruff check -o out.txt .",
    "uv run mypy --html-report /tmp/r",
    "uv run mypy --junit-xml out.xml",
]


@pytest.mark.parametrize("command", ROUTINE)
def test_routine_commands_pass(command: str) -> None:
    assert run_hook(command) is None


@pytest.mark.parametrize("command", NOT_ROUTINE)
def test_anything_else_asks(command: str) -> None:
    assert run_hook(command) == "ask"


def test_garbage_input_is_ignored_in_the_main_session() -> None:
    out = subprocess.run(
        [sys.executable, "-I", str(HOOK)], input="not json", capture_output=True, text=True
    )
    assert out.returncode == 0 and out.stdout == ""


@pytest.mark.skipif(not HAS_APPOPSY, reason="needs the project's virtualenv")
def test_pr_text_naming_your_apps_asks(tmp_path: Path) -> None:
    app_list = tmp_path / "my-apps.txt"
    app_list.write_text("package:org.example.privateapp\n")
    env = {"APPOPSY_THIRD_PARTY_LIST": str(app_list)}
    body = tmp_path / "body.md"
    body.write_text("Fixes the parser.\n")
    clean = f"gh pr create --base main --title 'Parser fix' --body-file {body}"
    assert run_hook(clean, env=env) is None
    assert run_hook("gh pr create --title 'org.example.privateapp fix' --body x", env=env)
    body.write_text("Seen with org.example.privateapp.\n")
    assert run_hook(clean, env=env) == "ask"
    # Publishing the app list itself is the worst case.
    assert run_hook(f"gh pr create --title t --body-file {app_list}", env=env) == "ask"


def test_pr_text_that_cant_be_checked_asks(tmp_path: Path) -> None:
    env = {"APPOPSY_THIRD_PARTY_LIST": str(tmp_path / "missing.txt")}
    assert run_hook("gh pr create --title t --body b", env=env) == "ask"


REVIEWER_OK = [
    "git diff origin/main...HEAD -- .claude",
    "git log --format=%B origin/main..HEAD | uv run appopsy mask",
    "git show HEAD:CLAUDE.md | head -50",
    "grep -rn 'foo$' docs",
    "uv run appopsy redact-fixture --check --third-party-list ~/.config/appopsy/my-apps.txt tests/fixtures 2>&1 | uv run appopsy mask",
    "uv run pytest -q tests/test_adb_allowlist.py",
    """echo '{"tool_input":{"command":"gh api -X POST x"}}' | python3 -I .claude/hooks/command_guard.py""",
    "find tests -name '*.py' | wc -l",
    "ls -la .claude 2>/dev/null",
]

REVIEWER_DENIED = [
    "git add -A",
    "git commit -m x",
    "git switch -c x",
    "git push origin x",
    "git -c core.pager=sh log",
    "git diff --output=x",
    "gh api repos/o/r",
    "gh pr create --title t --body b",
    "curl https://example.com",
    "touch notes.txt",
    "rm -rf cases",
    "echo x > notes.txt",
    "cat a >> b",
    "find . -name x -delete",
    "find . -exec sh -c 'x' ;",
    "sort -o out.txt in.txt",
    "rg --pre sh x",
    "uv run appopsy redact-fixture --out x tests/fixtures",
    "uv run appopsy redact-fixture --check --mapping m.txt x",
    "uv run pytest --basetemp=/x",
    "uv run python -c 'print(1)'",
    "python3 -c 'import os'",
    "GIT_EXTERNAL_DIFF=sh git diff",
    "echo $(whoami)",
    "sed -i s/a/b/ file",
    "adb shell getprop",
]


@pytest.mark.parametrize("command", REVIEWER_OK)
def test_reviewer_read_only_commands_pass(command: str) -> None:
    assert run_hook(command, reviewer=True) is None


@pytest.mark.parametrize("command", REVIEWER_DENIED)
def test_reviewer_everything_else_is_denied(command: str) -> None:
    assert run_hook(command, reviewer=True) == "deny"


def test_reviewer_mode_denies_unreadable_input() -> None:
    out = subprocess.run(
        [sys.executable, "-I", str(HOOK), "--reviewer"],
        input="not json",
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_settings_wire_the_hook_and_keep_permissions_narrow() -> None:
    settings = json.loads((CLAUDE / "settings.json").read_text())
    hooks = settings["hooks"]["PreToolUse"]
    assert any(
        h["matcher"] == "Bash" and "command_guard.py" in x["command"]
        for h in hooks
        for x in h["hooks"]
    )
    perms = settings["permissions"]
    allow = perms["allow"]
    # Nothing that pushes, deletes, merges, edits settings or touches the phone.
    for rule in allow:
        for bad in ("push", "pr merge", "delete", "rm ", "adb", "reset", "settings", "--force"):
            assert bad not in rule, rule
    assert "Bash(gh api *)" in allow  # safe only because of the hook above
    for rule in ("Bash(adb *)", "Bash(git push --force *)", "Bash(git push * --force *)"):
        assert rule in perms["deny"], rule
    for rule in (
        "Edit(**/.claude/settings.json)",
        "Edit(**/.claude/hooks/**)",
        "Edit(**/.claude/agents/**)",
        "Edit(**/.githooks/**)",
        "Edit(**/.github/**)",
        "Bash(gh pr merge *)",
    ):
        assert rule in perms["ask"], rule


def test_settings_local_is_ignored() -> None:
    # Read .gitignore rather than asking git: the pre-commit hook runs the tests
    # in an exported copy of the staged tree, which isn't a repository.
    lines = (ROOT / ".gitignore").read_text().splitlines()
    assert ".claude/settings.local.json" in lines


def frontmatter(name: str) -> str:
    return (CLAUDE / "agents" / f"{name}.md").read_text().split("---")[1]


@pytest.mark.parametrize("name", ["privacy-reviewer", "report-reader", "allowlist-guard"])
def test_reviewer_agents_are_read_only(name: str) -> None:
    front = frontmatter(name)
    tools_line = next(line for line in front.splitlines() if line.startswith("tools:"))
    tools = {t.strip() for t in tools_line.removeprefix("tools:").split(",")}
    assert tools <= {"Read", "Grep", "Glob", "Bash"}, tools
    denied = next(line for line in front.splitlines() if line.startswith("disallowedTools:"))
    for tool in ("Edit", "Write", "NotebookEdit", "WebFetch", "WebSearch"):
        assert tool in denied, tool
    if "Bash" in tools:
        # Bash inherits the project's allow rules, so the reviewer hook must hold it
        # to the read-only list.
        assert "matcher: Bash" in front
        assert 'command_guard.py" --reviewer' in front
