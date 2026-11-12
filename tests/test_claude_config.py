"""The checked-in Claude Code configuration (.claude/): the gh api guard hook, the
permissions in settings.json, and the read-only reviewer agents."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CLAUDE = ROOT / ".claude"
HOOK = CLAUDE / "hooks" / "gh_api_guard.py"


def run_hook(command: str) -> str | None:
    """The hook's permission decision for a Bash command (None: no opinion)."""
    event = {"tool_name": "Bash", "tool_input": {"command": command}}
    out = subprocess.run(
        [sys.executable, "-I", str(HOOK)],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    if not out.strip():
        return None
    decision: str = json.loads(out)["hookSpecificOutput"]["permissionDecision"]
    return decision


@pytest.mark.parametrize(
    "command",
    [
        "gh api repos/o/r",
        "gh api repos/o/r/rulesets --jq '.[].id'",
        "gh api -X GET repos/o/r/issues -f state=open",
        "gh api --method=get repos/o/r",
        "gh api -i repos/o/r/vulnerability-alerts 2>&1 | head -1",
        "gh api repos/o/r && gh api repos/o/r/rulesets",
        "gh pr view 12",
        "uv run pytest -q",
        "echo hi",
    ],
)
def test_get_requests_and_other_commands_pass(command: str) -> None:
    assert run_hook(command) is None


@pytest.mark.parametrize(
    "command",
    [
        "gh api -X POST repos/o/r/labels -f name=x",
        "gh api --method PATCH repos/o/r -F private=true",
        "gh api --method=DELETE repos/o/r/git/refs/heads/x",
        "gh api -XPUT repos/o/r/topics",
        "gh api repos/o/r/labels -f name=x",
        "gh api repos/o/r/labels -Fname=x",
        "gh api repos/o/r/labels --raw-field=name=x",
        "gh api repos/o/r/rulesets --input rules.json",
        "gh api graphql -f query='mutation { x }'",
        "gh api repos/o/r; gh api -X DELETE repos/o/r",
        "sh -c 'gh api -X DELETE repos/o/r'",
        "echo $(gh api -X POST repos/o/r/forks)",
        "gh api repos/o/r 'unterminated",
        "gh api -X",
    ],
)
def test_anything_else_asks(command: str) -> None:
    assert run_hook(command) == "ask"


def test_garbage_input_is_ignored() -> None:
    out = subprocess.run(
        [sys.executable, "-I", str(HOOK)], input="not json", capture_output=True, text=True
    )
    assert out.returncode == 0 and out.stdout == ""


def test_settings_wire_the_hook_and_keep_permissions_narrow() -> None:
    settings = json.loads((CLAUDE / "settings.json").read_text())
    hooks = settings["hooks"]["PreToolUse"]
    assert any(
        h["matcher"] == "Bash" and "gh_api_guard.py" in x["command"]
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
    for rule in ("Edit(**/.claude/settings.json)", "Bash(gh pr merge *)"):
        assert rule in perms["ask"], rule


def test_settings_local_is_ignored() -> None:
    # Read .gitignore rather than asking git: the pre-commit hook runs the tests
    # in an exported copy of the staged tree, which isn't a repository.
    lines = (ROOT / ".gitignore").read_text().splitlines()
    assert ".claude/settings.local.json" in lines


@pytest.mark.parametrize("name", ["privacy-reviewer", "report-reader", "allowlist-guard"])
def test_reviewer_agents_are_read_only(name: str) -> None:
    text = (CLAUDE / "agents" / f"{name}.md").read_text()
    front = text.split("---")[1]
    tools_line = next(line for line in front.splitlines() if line.startswith("tools:"))
    tools = {t.strip() for t in tools_line.removeprefix("tools:").split(",")}
    assert tools <= {"Read", "Grep", "Glob", "Bash"}, tools
    denied = next(line for line in front.splitlines() if line.startswith("disallowedTools:"))
    for tool in ("Edit", "Write", "NotebookEdit", "WebFetch", "WebSearch"):
        assert tool in denied, tool
