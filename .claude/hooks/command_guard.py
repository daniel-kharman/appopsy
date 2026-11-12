#!/usr/bin/env python3
"""PreToolUse hook for Bash: the commands .claude/settings.json pre-approves are
safe only in their routine forms, and a permission rule can only match a prefix.
This hook reads the whole command and closes the gap.

Default mode (the main session) answers "ask" when a pre-approved command is used
in a form that isn't routine:

- `gh api` that isn't plainly a GET: any method but GET, request fields or a body
  without `-X GET`, `--input`, `graphql`, a method-override header, or any flag
  it doesn't know (flags are an allowlist, so combined short flags like
  `-iXDELETE` and a value flag hiding a fake `-XGET` both ask);
- `gh pr create` for another repo (`-R`), or whose title or body names one of the
  maintainer's apps (the apps-only check runs on the text; the PR is public);
- `git commit` that skips the hooks (`-n`, `--no-v…`, any `hooksPath`), `git add`
  of ignored files (`-f`), `git switch`/`checkout` that discards work, and
  `git diff/log/show --output=FILE`;
- pytest, ruff and mypy flags that write or delete outside the repo or upload
  (`--basetemp`, `--junit…`, `--pastebin`, `-o`, `--output-file`, reports).

`--reviewer` mode (wired into the read-only reviewer agents) answers "deny" to
any command that isn't on a short read-only list, and to any redirection into a
file, so a reviewer can't write, push, or reach the network even though Bash
inherits the project's allow rules.

Asking is always safe: the hook never allows anything. Standard library only.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

SEPARATORS = {";", "&&", "||", "|", "|&", "&", "(", ")", "\n", ";;"}
REDIRECT_OPS = {">", ">>", "<", ">&", "<&", "&>", "&>>", ">|", "<<", "<<<"}
WRAPPERS = {"timeout", "time", "nice", "nohup", "stdbuf", "command", "builtin", "noglob"}
GH_API_TEXT = re.compile(r"\bgh\b\s+api\b")
ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
EXPANSION = re.compile(r"\$[({A-Za-z_]|`")

Command = list[str]


def parse(command: str) -> tuple[list[Command], list[str]] | None:
    """Simple commands (argv lists) and redirection targets, or None if unparseable."""
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return None
    commands: list[Command] = []
    targets: list[str] = []
    current: Command = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in SEPARATORS:
            if current:
                commands.append(current)
            current = []
        elif tok in REDIRECT_OPS:
            if current and current[-1].isdigit():
                current.pop()  # the fd number in `2>&1`
            if i + 1 < len(tokens):
                targets.append(tokens[i + 1])
                i += 1
        else:
            current.append(tok)
        i += 1
    if current:
        commands.append(current)
    return commands, targets


def strip_prefix(argv: Command) -> tuple[Command, list[str]]:
    """Drop leading VAR=value assignments and wrapper commands; return the assignments."""
    assignments: list[str] = []
    while argv and ASSIGNMENT.match(argv[0]):
        assignments.append(argv[0])
        argv = argv[1:]
    while argv and Path(argv[0]).name in WRAPPERS:
        argv = argv[1:]
        while argv and (argv[0].startswith("-") or argv[0][:1].isdigit()):
            argv = argv[1:]
    return argv, assignments


def is_cmd(argv: Command, *words: str) -> bool:
    return (
        len(argv) >= len(words)
        and Path(argv[0]).name == words[0]
        and argv[1 : len(words)] == list(words[1:])
    )


# --- gh api ------------------------------------------------------------------

GH_BOOL = {"-i", "--include", "--paginate", "--silent", "--slurp", "--verbose"}
GH_VALUE = {"-H", "--header", "-q", "--jq", "-t", "--template", "-p", "--preview",
            "--hostname", "--cache"}  # fmt: skip
GH_FIELD = {"-f", "--raw-field", "-F", "--field"}


def gh_api_reason(args: Command) -> str | None:
    method: str | None = None
    fields = False
    positionals: list[str] = []
    headers: list[str] = []
    it = iter(args)
    for a in it:
        name, eq, attached = a.partition("=") if a.startswith("--") else (a, "", "")
        if a == "--":
            positionals.extend(it)
            break
        if not a.startswith("-") or a == "-":
            positionals.append(a)
        elif name in ("-X", "--method"):
            method = (attached if eq else next(it, "")).upper()
        elif a.startswith("-X") and len(a) > 2:
            method = a[2:].upper()
        elif name in GH_FIELD:
            fields = True
            if not eq:
                next(it, None)
        elif len(a) > 2 and a[:2] in ("-f", "-F"):
            fields = True
        elif name in GH_VALUE:
            value = attached if eq else next(it, "")
            if name in ("-H", "--header"):
                headers.append(value)
        elif len(a) > 2 and a[:2] in ("-H", "-q", "-t", "-p"):
            if a[:2] == "-H":
                headers.append(a[2:])
        elif a in GH_BOOL:
            pass
        else:
            return f"gh api with flag {a!r}, which this guard doesn't know"
    if len(positionals) != 1:
        return "gh api without exactly one endpoint"
    if positionals[0].strip("/").lower() == "graphql":
        return "gh api graphql (GraphQL requests are POSTs)"
    if any("method-override" in h.lower() for h in headers):
        return "gh api with a method-override header"
    if method is not None and method != "GET":
        return f"gh api with method {method or '(missing)'}"
    if method is None and fields:
        return "gh api with request fields (gh sends these as a POST)"
    return None


# --- gh pr create ----------------------------------------------------------------


def pr_create_reason(args: Command) -> str | None:
    texts: list[str] = []
    files: list[str] = []
    it = iter(args)
    for a in it:
        name, eq, attached = a.partition("=") if a.startswith("--") else (a, "", "")
        if name in ("-R", "--repo") or a.startswith("-R"):
            return "gh pr create for another repository"
        if name in ("-t", "--title", "-b", "--body"):
            texts.append(attached if eq else next(it, ""))
        elif name in ("-F", "--body-file"):
            files.append(attached if eq else next(it, ""))
    if "-" in files:
        return "gh pr create with the body on stdin, which can't be checked"
    return apps_check(texts, files)


def apps_check(texts: list[str], files: list[str]) -> str | None:
    """Run the apps-only check over PR text; a reason to ask, or None if clean."""
    project = Path(os.environ.get("CLAUDE_PROJECT_DIR", Path(__file__).resolve().parents[2]))
    appopsy = project / ".venv" / "bin" / "appopsy"
    app_list = Path(
        os.environ.get("APPOPSY_THIRD_PARTY_LIST", Path.home() / ".config/appopsy/my-apps.txt")
    )
    if not appopsy.exists() or not app_list.is_file():
        return "PR text can't be checked for your apps (no .venv or no app list)"
    try:
        body = "\n".join(texts + [Path(f).read_text(errors="replace") for f in files])
    except OSError:
        return "PR body file can't be read for the apps check"
    with tempfile.TemporaryDirectory() as tmp:
        text_file = Path(tmp) / "pr-text.md"
        text_file.write_text(body)
        result = subprocess.run(
            [str(appopsy), "redact-fixture", "--check", "--apps-only",
             "--third-party-list", str(app_list), str(text_file)],
            capture_output=True, check=False, timeout=50,
        )  # fmt: skip
    if result.returncode != 0:
        return "PR title or body names one of your apps (or the check failed)"
    return None


# --- git, pytest, ruff, mypy ---------------------------------------------------


def short_flag(arg: str, letter: str) -> bool:
    """Whether a short-option group such as `-Af` contains `letter`."""
    return arg.startswith("-") and not arg.startswith("--") and letter in arg[1:]


def git_reason(argv: Command) -> str | None:
    args = argv[1:]
    if any("hookspath" in a.lower() for a in args):
        return "git with core.hooksPath"
    # Skip global options to find the subcommand.
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace") else 1
    if i >= len(args):
        return None
    sub, rest = args[i], args[i + 1 :]
    if sub in ("commit", "push"):
        for a in rest:
            if a.startswith("--no-v"):
                return f"git {sub} skipping the hooks"
            if sub == "commit" and a.startswith("-") and not a.startswith("--"):
                for ch in a[1:]:
                    if ch == "n":
                        return "git commit -n skips the hooks"
                    if ch in "mFCct":
                        break  # the rest of the token is this flag's value
    if sub in ("diff", "log", "show") and any(a.startswith("--output") for a in rest):
        return f"git {sub} --output writes a file"
    if sub == "add" and any(a.startswith("--f") or short_flag(a, "f") for a in rest):
        return "git add -f stages ignored files (cases/, local settings)"
    if sub in ("switch", "checkout") and any(
        a.startswith(("--f", "--discard")) or short_flag(a, "f") for a in rest
    ):
        return f"git {sub} that can discard uncommitted work"
    return None


def tool_reason(argv: Command) -> str | None:
    if is_cmd(argv, "uv", "run", "pytest"):
        for a in argv[3:]:
            if a.startswith(("--basetemp", "--junit", "--pastebin", "--result-log",
                             "--override-ini", "-o")):  # fmt: skip
                return f"pytest {a.split('=')[0]} writes, deletes or uploads"
    if is_cmd(argv, "uv", "run", "ruff"):
        for a in argv[3:]:
            if a.startswith(("--output-file", "-o")):
                return "ruff --output-file writes a file"
    if is_cmd(argv, "uv", "run", "mypy"):
        for a in argv[3:]:
            if a.startswith("--") and ("report" in a or "junit" in a):
                return f"mypy {a.split('=')[0]} writes a report"
    return None


def main_reason(command: str) -> str | None:
    parsed = parse(command)
    if parsed is None:
        return "a command that can't be parsed" if GH_API_TEXT.search(command) else None
    commands, _ = parsed
    gh_api_calls = 0
    for raw in commands:
        argv, _ = strip_prefix(raw)
        if not argv:
            continue
        reason: str | None = None
        if is_cmd(argv, "gh", "api"):
            gh_api_calls += 1
            reason = gh_api_reason(argv[2:])
        elif is_cmd(argv, "gh", "pr", "create"):
            reason = pr_create_reason(argv[3:])
        elif Path(argv[0]).name == "git":
            reason = git_reason(argv)
        else:
            reason = tool_reason(argv)
        if reason:
            return reason
    dequoted = command.replace('"', "").replace("'", "").replace("\\", "")
    if len(GH_API_TEXT.findall(dequoted)) != gh_api_calls:
        return "gh api inside quotes, a subshell or another command; can't confirm it is a GET"
    return None


# --- reviewer mode ---------------------------------------------------------------

READ_ONLY_GIT = {"diff", "log", "show", "status", "ls-files", "rev-parse", "rev-list",
                 "merge-base", "blame", "cat-file"}  # fmt: skip
READ_ONLY_TOOLS = {"grep", "egrep", "rg", "cat", "head", "tail", "wc", "ls", "stat", "file",
                   "echo", "printf", "pwd", "cut", "tr", "diff", "comm", "basename",
                   "dirname", "realpath", "find", "sort", "jq", "true", "test"}  # fmt: skip
SAFE_ASSIGNMENTS = re.compile(r"(TZ|LANG|LC_[A-Z]+)=")


def reviewer_reason(command: str) -> str | None:
    parsed = parse(command)
    if parsed is None:
        return "a command that can't be parsed"
    commands, targets = parsed
    for t in targets:
        if t != "/dev/null" and not t.isdigit():
            return f"redirection into {t!r}"
    for raw in commands:
        if any(EXPANSION.search(tok) for tok in raw):
            return "command or variable substitution"
        argv, assignments = strip_prefix(raw)
        if any(not SAFE_ASSIGNMENTS.match(a) for a in assignments):
            return "environment assignment"
        if not argv:
            continue
        name = Path(argv[0]).name
        if name == "git":
            reason = git_reason(argv)
            if reason:
                return reason
            subs = [a for a in argv[1:] if not a.startswith("-")]
            if not subs or subs[0] not in READ_ONLY_GIT or "-c" in argv[1:]:
                return "git command that isn't read-only"
        elif name in READ_ONLY_TOOLS:
            if name == "find" and any(
                a in ("-delete", "-exec", "-execdir", "-ok", "-okdir")
                or a.startswith("-fprint") or a == "-fls"
                for a in argv
            ):  # fmt: skip
                return "find with an action that runs or writes"
            if name == "sort" and any(a.startswith(("-o", "--output")) for a in argv):
                return "sort -o writes a file"
            if name == "rg" and any(a.startswith("--pre") for a in argv):
                return "rg --pre runs a command"
        elif is_cmd(argv, "uv", "run", "appopsy", "mask"):
            pass
        elif is_cmd(argv, "uv", "run", "appopsy", "redact-fixture"):
            if "--check" not in argv or any(
                a.startswith(("--out", "-o", "--mapping", "--force")) for a in argv
            ):
                return "redact-fixture other than --check"
        elif is_cmd(argv, "uv", "run", "pytest"):
            reason = tool_reason(argv)
            if reason:
                return reason
        elif (
            name in ("python3", "python")
            and argv[1:2] == ["-I"]
            and argv[2:3]
            and argv[2].endswith(".claude/hooks/command_guard.py")
            and argv[3:] in ([], ["--reviewer"])
        ):
            pass  # probing this guard
        else:
            return f"{name} isn't on the reviewers' read-only list"
    return None


def main() -> int:
    reviewer = "--reviewer" in sys.argv[1:]
    try:
        event = json.load(sys.stdin)
        command = event.get("tool_input", {}).get("command", "")
    except (ValueError, AttributeError):
        command = None
    if not isinstance(command, str):
        if not reviewer:
            return 0  # not a Bash event we understand; normal permission rules apply
        command = ""
        reason: str | None = "a tool call this guard can't read"
    else:
        reason = reviewer_reason(command) if reviewer else main_reason(command)
    if reason:
        decision = "deny" if reviewer else "ask"
        prefix = "Reviewers are read-only" if reviewer else "Not a routine command"
        out = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": f"{prefix}: {reason}.",
            }
        }
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
