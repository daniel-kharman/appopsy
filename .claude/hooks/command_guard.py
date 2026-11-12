#!/usr/bin/env python3
"""PreToolUse hook for Bash: the commands .claude/settings.json pre-approves are
safe only in their routine forms, and a permission rule can only match a prefix.
This hook reads the whole command and **fails closed**: whatever it can't fully
account for is not routine.

1. A character scan runs before any parsing. Outside single quotes, anything the
   shell would expand or reinterpret (`$`, backticks, braces, globs, `#`,
   backslashes) is refused; a quoted heredoc body (`<<'EOF'`) is literal and
   allowed; an unquoted newline separates commands.
2. Each pre-approved command is then checked against an allowlist of its
   flags. An unknown flag, an environment assignment or a git global option in
   front of it, or a path outside the repo is refused.

Default mode (the main session) answers "ask" for a refused command, and only
when it involves a command settings.json pre-approves (gh, git, uv); everything
else gets the normal permission prompt anyway. Notable refusals: `gh api` that
isn't a plain GET to github.com, `gh pr create` for another repo or whose text
names one of the maintainer's apps (the apps-only check runs on it), any
`git push` other than `-u origin <feature-branch>`, commits that skip hooks,
`git add -f`, and tool flags that write, delete or upload.

Any git or gh subcommand the guard doesn't explicitly handle asks, so safety
doesn't depend on how narrow settings.json's patterns are.

`--reviewer` mode (the read-only reviewer agents) answers "deny" to any command
that isn't on a short read-only list (read-only git, the repo's check commands,
pipe filters; no file-reading tools, since grep, cat and ls may be anything on
PATH), redirects into a file, or touches a path outside the repo or inside
cases/ or reports/. Reviewers read files through Read, Grep and Glob, which are
checked by path the same way. The maintainer's app list is readable
only through `redact-fixture --check --third-party-list`.

The hook fails closed: if it crashes or times out, the answer is "ask" (or
"deny" for a reviewer), never silence. It never allows anything. Standard
library only.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SEPARATORS = {";", "&&", "||", "|", "|&", "&", "(", ")", ";;"}
REDIRECT_OPS = {">", ">>", "<", ">&", "<&", "&>", "&>>", ">|", "<<<"}
# Commands that run another command. Only `timeout N` is routine: the others take
# options that write files (`time -o`), change the environment (`env`), or hide
# the real command from prefix rules (`xargs`, `exec`, `eval`).
WRAPPERS = {"timeout", "time", "nice", "nohup", "stdbuf", "command", "builtin", "noglob",
            "env", "xargs", "exec", "eval", "sudo", "doas", "nocorrect"}  # fmt: skip
COVERED_TEXT = re.compile(r"\b(gh|git|uv|pytest|ruff|mypy)\b", re.IGNORECASE)
GH_API_TEXT = re.compile(r"\bgh\b\s+api\b")
ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")  # X=… and X+=…
HEREDOC = re.compile(r"<<(-?)[ \t]*(?:'([^'\n]+)'|\"([^\"\n]+)\")")
GUARD_PATH = ".claude/hooks/command_guard.py"

Command = list[str]

# One time budget for the whole decision, well under the hook's timeout in
# settings.json, so the guard answers before Claude Code would kill it.
BUDGET_SECONDS = 45.0
DEADLINE = time.monotonic() + BUDGET_SECONDS


def budget(limit: float) -> float:
    """A subprocess timeout within the remaining budget; refuse once it is spent."""
    left = DEADLINE - time.monotonic()
    if left < 1:
        raise Refused("the guard ran out of time checking this")
    return min(limit, left)


class Refused(Exception):
    """The command uses something the guard won't vouch for."""


# --- 1. Character scan --------------------------------------------------------


def scan(command: str) -> str:
    """The command with quoted heredoc bodies removed and unquoted newlines as `;`.

    Raises Refused for anything the shell would expand or reinterpret.
    """
    out: list[str] = []
    pending: list[tuple[str, bool]] = []  # heredoc delimiters awaiting their body
    i, n = 0, len(command)
    word_start = True
    while i < n:
        c = command[i]
        if c == "'":
            end = command.find("'", i + 1)
            if end < 0:
                raise Refused("unbalanced quotes")
            out.append(command[i : end + 1])
            i, word_start = end + 1, False
            continue
        if c == '"':
            j = i + 1
            while j < n and command[j] != '"':
                if command[j] in "$`\\":
                    raise Refused("expansion or escape inside double quotes")
                j += 1
            if j >= n:
                raise Refused("unbalanced quotes")
            out.append(command[i : j + 1])
            i, word_start = j + 1, False
            continue
        if command.startswith("<<<", i):  # a here-string: its word is scanned as usual
            out.append("<<<")
            i, word_start = i + 3, True
            continue
        if command.startswith("<<", i):
            m = HEREDOC.match(command, i)
            if not m:
                raise Refused("a heredoc whose delimiter isn't quoted (its body would expand)")
            pending.append((m.group(2) or m.group(3), m.group(1) == "-"))
            i, word_start = m.end(), True
            continue
        if c == "\n":
            i += 1
            for delimiter, strip_tabs in pending:
                while True:
                    end = command.find("\n", i)
                    line = command[i:] if end < 0 else command[i:end]
                    i = n if end < 0 else end + 1
                    if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                        break
                    if end < 0:
                        raise Refused("a heredoc without its closing delimiter")
            pending = []
            out.append(" ; ")
            word_start = True
            continue
        if c in "$`":
            raise Refused("command, variable or ANSI-C expansion")
        if c in "()":
            raise Refused("parentheses (subshell, process substitution, zsh glob qualifier)")
        if c in "{}":
            raise Refused("brace expansion")
        if c in "*?[]":
            raise Refused("a glob outside quotes")
        if c == "\\":
            raise Refused("a backslash outside quotes")
        if c == "#":
            raise Refused("# outside quotes")
        if c == "~" and not (word_start and command.startswith("~/", i)):
            raise Refused("~ other than ~/ at the start of a word")
        out.append(c)
        word_start = c in " \t;&|()<>"
        i += 1
    if pending:
        raise Refused("a heredoc without its body")
    return "".join(out)


def parse(command: str) -> tuple[list[Command], list[str], list[list[str]]]:
    """Simple commands (argv), redirection targets, and each command's assignments."""
    text = scan(command)
    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|()<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError as e:
        raise Refused("a command that can't be parsed") from e
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
            if i + 1 >= len(tokens):
                raise Refused("a redirection without a target")
            targets.append(tokens[i + 1])
            i += 1
        elif set(tok) <= set(";&|()<>"):
            raise Refused(f"the shell operator {tok!r}")
        else:
            current.append(tok)
        i += 1
    if current:
        commands.append(current)
    assignments: list[list[str]] = []
    stripped: list[Command] = []
    for argv in commands:
        assigned: list[str] = []
        while argv and ASSIGNMENT.match(argv[0]):
            assigned.append(argv[0])
            argv = argv[1:]
        while argv and Path(argv[0]).name.lower() in WRAPPERS:
            if argv[0] == "timeout" and len(argv) > 2 and re.fullmatch(r"\d+[smhd]?", argv[1]):
                argv = argv[2:]
            else:
                raise Refused(f"the wrapper {argv[0]!r} (only `timeout N` is routine)")
        stripped.append(argv)
        assignments.append(assigned)
    return stripped, targets, assignments


# --- 2. Per-command allowlists ---------------------------------------------------


def is_cmd(argv: Command, *words: str) -> bool:
    """argv starts with these words; the program name is compared case-insensitively
    (macOS file systems resolve `GIT` to git)."""
    return (
        len(argv) >= len(words)
        and Path(argv[0]).name.lower() == words[0]
        and argv[1 : len(words)] == list(words[1:])
    )


def repo_path(arg: str) -> bool:
    """A path inside the repo: relative, and never climbing out with `..`."""
    path = arg.split("::", 1)[0]
    return not path.startswith(("/", "~")) and ".." not in Path(path).parts


class Flags:
    """Walk argv against an allowlist of boolean and value-taking flags."""

    def __init__(self, args: Command, booleans: set[str], values: set[str]) -> None:
        self.args, self.booleans, self.values = args, booleans, values

    def walk(self) -> list[tuple[str, str | None]]:
        """(flag, value) pairs; positionals come back as ("", arg). Raises on unknowns."""
        out: list[tuple[str, str | None]] = []
        it = iter(self.args)
        for a in it:
            if a == "--":
                out.extend(("", rest) for rest in it)
                break
            if not a.startswith("-") or a == "-":
                out.append(("", a))
                continue
            name, eq, attached = a.partition("=") if a.startswith("--") else (a, "", "")
            if name in self.values:
                value = attached if eq else next(it, None)
                if value is None:
                    raise Refused(f"{name} without a value")
                out.append((name, value))
            elif not a.startswith("--") and a[:2] in self.values and len(a) > 2:
                out.append((a[:2], a[2:]))  # attached short value, e.g. -tTitle
            elif a in self.booleans:
                out.append((a, None))
            else:
                raise Refused(f"the flag {a!r}, which this guard doesn't know")
        return out


# gh api: GET to github.com only.
GH_API_BOOL = {"-i", "--include", "--paginate", "--silent", "--slurp", "--verbose"}
GH_API_VALUE = {"-H", "--header", "-q", "--jq", "-t", "--template", "-p", "--preview",
                "--cache", "-X", "--method", "-f", "--raw-field", "-F", "--field"}  # fmt: skip


def check_gh_api(args: Command) -> None:
    method, fields, endpoints = None, False, []
    for flag, value in Flags(args, GH_API_BOOL, GH_API_VALUE).walk():
        if not flag:
            endpoints.append(value or "")
        elif flag in ("-X", "--method"):
            method = (value or "").upper()
        elif flag in ("-f", "--raw-field", "-F", "--field"):
            fields = True
            if "=@" in (value or "") or (value or "").startswith("@"):
                raise Refused("gh api sending a file's contents")
        elif flag in ("-H", "--header") and "override" in (value or "").lower():
            raise Refused("gh api with a method-override header")
    if len(endpoints) != 1:
        raise Refused("gh api without exactly one endpoint")
    endpoint = endpoints[0]
    if "://" in endpoint or endpoint.startswith("//"):
        raise Refused("gh api to a full URL")
    if endpoint.rstrip("/").rsplit("/", 1)[-1].lower() == "graphql":
        raise Refused("gh api graphql (GraphQL requests are POSTs)")
    if method is not None and method != "GET":
        raise Refused(f"gh api with method {method}")
    if method is None and fields:
        raise Refused("gh api with request fields (gh sends these as a POST)")


GH_PR_BOOL = {"-d", "--draft"}
GH_PR_VALUE = {"-B", "--base", "-H", "--head", "-t", "--title", "-b", "--body",
               "-F", "--body-file", "-l", "--label"}  # fmt: skip


def check_pr_create(args: Command, roots: Roots) -> None:
    texts: list[str] = []
    files: list[str] = []
    for flag, value in Flags(args, GH_PR_BOOL, GH_PR_VALUE).walk():
        if not flag:
            raise Refused("gh pr create with an unexpected argument")
        if flag in ("-t", "--title", "-b", "--body", "-l", "--label"):
            texts.append(value or "")
        elif flag in ("-F", "--body-file"):
            files.append(value or "")
    if "-" in files:
        raise Refused("gh pr create with the body on stdin, which can't be checked")
    for f in files:
        if not roots.may_publish(f):
            raise Refused("gh pr create publishing a file from outside the repo and scratchpad")
    apps_check(texts, files)


class Roots:
    """Where a PR body file may come from: the session scratchpad, or the repo
    outside its personal-data folders."""

    PRIVATE = ("cases", "reports", ".venv", ".git")

    def __init__(self, project: str, scratchpad: str | None, cwd: str | None) -> None:
        self.project = Path(project).resolve() if project else None
        self.scratchpad = Path(scratchpad).resolve() if scratchpad else None
        self.cwd = Path(cwd) if cwd else Path.cwd()

    def may_publish(self, name: str) -> bool:
        path = (self.cwd / Path(name).expanduser()).resolve()
        if self.scratchpad and path.is_relative_to(self.scratchpad):
            return True
        if self.project and path.is_relative_to(self.project):
            first = path.relative_to(self.project).parts[:1]
            return bool(first) and first[0] not in self.PRIVATE
        return False


def apps_check(texts: list[str], files: list[str]) -> None:
    """Run the apps-only check over PR text; refuse unless it is clean."""
    project = Path(os.environ.get("CLAUDE_PROJECT_DIR", Path(__file__).resolve().parents[2]))
    appopsy = project / ".venv" / "bin" / "appopsy"
    app_list = Path(
        os.environ.get("APPOPSY_THIRD_PARTY_LIST", Path.home() / ".config/appopsy/my-apps.txt")
    )
    if not appopsy.exists() or not app_list.is_file():
        raise Refused("PR text can't be checked for your apps (no .venv or no app list)")
    try:
        body = "\n".join(texts + [Path(f).read_text(errors="replace") for f in files])
    except OSError as e:
        raise Refused("PR body file can't be read for the apps check") from e
    with tempfile.TemporaryDirectory() as tmp:
        text_file = Path(tmp) / "pr-text.md"
        text_file.write_text(body)
        try:
            result = subprocess.run(
                [str(appopsy), "redact-fixture", "--check", "--apps-only",
                 "--third-party-list", str(app_list), str(text_file)],
                capture_output=True, check=False, timeout=budget(30),
            )  # fmt: skip
        except subprocess.TimeoutExpired as e:
            raise Refused("the apps check on the PR text timed out") from e
        except OSError as e:
            raise Refused("the apps check on the PR text couldn't run") from e
    if result.returncode != 0:
        raise Refused("PR title or body names one of your apps (or the check failed)")


GIT_READ = {"status", "diff", "log", "show", "rev-parse", "rev-list", "ls-files",
            "merge-base", "blame", "cat-file"}  # fmt: skip
COMMIT_BOOL = {"--amend", "--no-edit", "--quiet", "--all", "--signoff", "--allow-empty"}
COMMIT_VALUE = {"-m", "--message", "-F", "--file"}


GIT_RISKY = ("--output", "--ext-diff", "--textconv")


def writes_or_runs(arg: str) -> bool:
    """`--output=FILE`, `--ext-diff`, `--textconv`, or an abbreviation of one."""
    name = arg.split("=", 1)[0]
    return name.startswith(GIT_RISKY) or (
        len(name) >= 4 and any(option.startswith(name) for option in GIT_RISKY)
    )


def short_group(arg: str, letters: str) -> bool:
    """Whether a short-option group such as `-co` contains one of `letters`."""
    return arg.startswith("-") and not arg.startswith("--") and bool(set(arg[1:]) & set(letters))


def check_git(argv: Command, *, reviewer: bool = False, roots: Roots | None = None) -> None:
    if len(argv) < 2 or argv[1].startswith("-"):
        raise Refused("git with a global option (-c, -C, --config-env, …)")
    sub, args = argv[1], argv[2:]
    if any("hookspath" in a.lower() for a in args):
        raise Refused("git with core.hooksPath")
    if sub in GIT_READ:
        if any(writes_or_runs(a) for a in args):
            raise Refused(f"git {sub} with an option that writes a file or runs a program")
        if reviewer and any(
            a.startswith(("--no-index", "--ignored", "--others"))
            or (sub == "ls-files" and short_group(a, "oi"))
            for a in args
        ):  # fmt: skip
            raise Refused(f"git {sub} reading files outside git or listing ignored ones")
        return
    if sub == "branch":
        if args in ([], ["--show-current"], ["--list"]):
            return
        raise Refused("git branch other than --show-current/--list")
    if reviewer:
        raise Refused(f"git {sub} isn't read-only")
    if sub == "commit":
        check_commit(args)
    elif sub == "add":
        for a in args:
            if (
                a.startswith("-")
                and a not in ("--", "--all", "--update")
                and not re.fullmatch(r"-[Au]+", a)
            ):
                raise Refused(f"git add {a} (only -A/-u; -f would stage ignored files)")
    elif sub in ("switch", "checkout"):
        flag = "-c" if sub == "switch" else "-b"
        if not (
            len(args) in (2, 3) and args[0] == flag and not any(a.startswith("-") for a in args[1:])
        ):
            raise Refused(f"git {sub} other than `{flag} <new-branch> [<start>]`")
    elif sub == "push":
        check_push(args, roots)
    else:
        raise Refused(f"git {sub}, which this guard doesn't handle")


# A branch name with nothing that could make it another ref, a refspec (`a:b`,
# `+a` forces) or an option.
BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")
PROTECTED = {"main", "master", "head"}
# Short-name prefixes git expands to other refs (heads/main is main).
REF_PREFIXES = {"heads", "tags", "remotes", "refs", "origin"}
# Config that changes where `git push -u origin X` goes or what it sends, or that
# runs another program; core.hooksPath is checked separately.
PUSH_CONFIG = (
    r"^(remote\.origin\.(push|pushurl|receivepack|mirror)|url\..*insteadof"
    r"|push\.followtags|core\.sshcommand|include\.path|includeif\..*)$"
)


def check_push(args: Command, roots: Roots | None) -> None:
    """Only `git push -u origin <branch>` is routine, for a local branch other than
    main, from this repo, with config that can't redirect it.

    Anything else (force, --no-verify, another remote, a refspec, tags, --all,
    --delete, several branches) asks. The name is resolved by git, because git
    expands short names: `heads/main` is main, and a tag beats a branch.
    """
    if len(args) != 3 or args[:2] != ["-u", "origin"]:
        raise Refused("git push other than `git push -u origin <branch>`")
    branch = args[2]
    if (
        not BRANCH.fullmatch(branch)
        or branch.lower() in PROTECTED
        or branch.split("/", 1)[0].lower() in REF_PREFIXES
        or re.fullmatch(r"[A-Z_]*HEAD", branch)
        or ".." in branch
        or branch.endswith((".lock", "/", "."))
    ):
        raise Refused(f"git push of {branch!r} (only a feature branch, never main)")
    if (
        roots is None
        or roots.project is None
        or not roots.cwd.resolve().is_relative_to(roots.project)
    ):
        raise Refused("git push from outside this repository")

    def git(*cmd: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(roots.cwd), *cmd],  # noqa: S607 (git from PATH, like the shell)
            capture_output=True, text=True, check=False, timeout=budget(10),
        )  # fmt: skip

    try:
        full = git("rev-parse", "--symbolic-full-name", branch)
        tag = git("show-ref", "--verify", "--quiet", f"refs/tags/{branch}")
        config = git("config", "--get-regexp", PUSH_CONFIG)
        hooks = git("config", "--get", "core.hooksPath")
    except (OSError, subprocess.SubprocessError) as e:
        raise Refused("git push that can't be verified (git didn't run)") from e
    if full.returncode != 0 or full.stdout.strip() != f"refs/heads/{branch}":
        raise Refused(f"git push of {branch!r}, which isn't a local branch")
    if tag.returncode == 0:
        raise Refused(f"git push of {branch!r}, which is also a tag")
    if config.stdout.strip():
        raise Refused(
            "git push with config that redirects or widens it (push refspec, URL rewrite, …)"
        )
    if hooks.stdout.strip() != ".githooks":
        raise Refused("git push without core.hooksPath=.githooks (the pre-push hook wouldn't run)")


def check_commit(args: Command) -> None:
    it = iter(args)
    for a in it:
        if a == "--":
            break
        if not a.startswith("-"):
            continue  # a pathspec
        name, eq, _ = a.partition("=") if a.startswith("--") else (a, "", "")
        if a in COMMIT_BOOL:
            continue
        if name in COMMIT_VALUE:
            if not eq and next(it, None) is None:
                raise Refused(f"git commit {name} without a value")
            continue
        if a.startswith("--"):
            raise Refused(f"git commit {a} (hooks must run; unknown options ask)")
        for k, ch in enumerate(a[1:]):
            if ch in "qas":
                continue
            if ch in "mF":
                if k == len(a) - 2 and next(it, None) is None:
                    raise Refused(f"git commit -{ch} without a value")
                break
            raise Refused(f"git commit -{ch} (-n skips the hooks; unknown options ask)")


PYTEST_BOOL = {"-q", "-qq", "-v", "-vv", "-x", "-s", "-l", "--lf", "--ff", "--sw",
               "--no-header", "--co", "--collect-only", "--strict-markers"}  # fmt: skip
PYTEST_VALUE = {"-k", "-m", "--tb", "--maxfail", "--durations", "-p"}
RUFF_BOOL = {"--check", "--diff", "-q", "--quiet", "--fix", "--no-fix", "--statistics",
             "--show-fixes"}  # fmt: skip
RUFF_VALUE = {"--select", "--ignore", "--output-format"}


def check_tool(argv: Command) -> None:
    tool, args = argv[2], argv[3:]
    if tool == "pytest":
        args = [a for a in args if not re.fullmatch(r"-r[a-zA-Z]+|-[qvxsl]+", a) or a == "-p"]
        pairs = Flags(args, PYTEST_BOOL, PYTEST_VALUE).walk()
        if any(f == "-p" and not (v or "").startswith("no:") for f, v in pairs):
            raise Refused("pytest -p loading a plugin (only -p no:… is routine)")
    elif tool == "ruff":
        if not args or args[0] not in ("check", "format"):
            raise Refused("ruff other than check/format")
        pairs = Flags(args[1:], RUFF_BOOL, RUFF_VALUE).walk()
    else:  # mypy
        pairs = Flags(args, set(), set()).walk()
    for flag, value in pairs:
        if not flag and not repo_path(value or ""):
            raise Refused(f"{tool} on a path outside the repo")


def dequote(command: str) -> str:
    return command.replace('"', "").replace("'", "").replace("\\", "")


def main_check(command: str, roots: Roots) -> None:
    try:
        commands, targets, assignments = parse(command)
    except Refused:
        # Only commands settings.json pre-approves need the guard; anything else
        # gets the normal prompt. Quotes can split a word (`gi""t`), so look at
        # the text without them.
        if COVERED_TEXT.search(dequote(command)):
            raise
        return
    gh_api_calls = 0
    any_covered = False
    for argv, assigned in zip(commands, assignments, strict=True):
        if not argv:
            continue
        if is_cmd(argv, "uv", "run") and len(argv) > 2:
            if argv[2] == "--":
                argv = ["uv", "run", *argv[3:]]
            elif argv[2].startswith("-"):
                raise Refused("uv run with options before the command")
            if len(argv) > 2 and Path(argv[2]).name.lower() in ("git", "gh"):
                argv = argv[2:]  # `uv run git …` is still git
        name = Path(argv[0]).name.lower()
        covered = name in ("gh", "git") or is_cmd(argv, "uv", "run")
        any_covered = any_covered or covered
        if covered and assigned:
            raise Refused("an environment assignment in front of a pre-approved command")
        if is_cmd(argv, "gh", "api"):
            gh_api_calls += 1
            check_gh_api(argv[2:])
        elif is_cmd(argv, "gh", "pr", "create"):
            check_pr_create(argv[3:], roots)
        elif is_cmd(argv, "gh", "pr", "view"):
            pass  # read-only
        elif name == "gh":
            raise Refused(f"gh {' '.join(argv[1:3])}, which this guard doesn't handle")
        elif name == "git":
            if argv[1:2] == ["push"] and any(c[:1] == ["cd"] for c in commands):
                raise Refused("git push after cd (which repository's origin?)")
            check_git(argv, roots=roots)
        elif any(is_cmd(argv, "uv", "run", t) for t in ("pytest", "ruff", "mypy")):
            check_tool(argv)
    if any_covered and any(t != "/dev/null" and not t.isdigit() for t in targets):
        raise Refused("a pre-approved command redirected into a file")
    if len(GH_API_TEXT.findall(dequote(command))) != gh_api_calls:
        raise Refused("gh api inside quotes or another command; can't confirm it is a GET")


# --- reviewer mode ---------------------------------------------------------------

# Reviewers read files with the Read, Grep and Glob tools, which this guard checks
# by path. Their Bash has no file-reading tools at all: names like grep, cat and
# ls resolve to whatever is on PATH (ugrep, bat or eza on some machines), whose
# flags can run programs, write files or list cases/. Bash keeps read-only git
# with checked paths, the repo's own check commands, and filters that read only
# a pipe.
REVIEWER_GIT = {"status", "diff", "log", "show", "rev-parse", "rev-list", "ls-files",
                "merge-base"}  # fmt: skip
# Options that write, run a program, read outside git, or list ignored files;
# git accepts unambiguous abbreviations, so prefixes of these count too.
REVIEWER_GIT_RISKY = ("--output", "--ext-diff", "--textconv", "--no-index", "--ignored",
                      "--others", "--contents")  # fmt: skip
# Pipe filters: no operands (so no files), only these short flags, numbers as values.
FILTERS = {"head": "nc", "tail": "nc", "wc": "lwcm", "sort": "nrufhVb", "uniq": "cdui"}
BUILTINS = {"echo", "printf", "true", "pwd"}
PRIVATE_DIRS = ("cases", "reports")
SAFE_ASSIGNMENT = re.compile(r"(TZ|LANG|LC_[A-Z]+)=")


def readable(arg: str, cwd: Path, roots: Roots) -> bool:
    """A path a reviewer may read: inside the repo (after symlinks), not in cases/ or
    reports/ in any letter case (macOS file systems ignore case). The app list is
    outside the repo, so it never qualifies."""
    if roots.project is None:
        return False
    path = (cwd / Path(arg).expanduser()).resolve()
    if not path.is_relative_to(roots.project):
        return False
    parts = path.relative_to(roots.project).parts
    return not (parts and parts[0].casefold() in PRIVATE_DIRS)


def is_root(arg: str, cwd: Path, roots: Roots) -> bool:
    """The repo root: cases/ and reports/ live directly under it, so a recursive read
    from there reaches them. Recursive reads must name subdirectories."""
    return roots.project is not None and (cwd / Path(arg).expanduser()).resolve() == roots.project


def risky_git_option(arg: str) -> bool:
    name = arg.split("=", 1)[0]
    return name.startswith(REVIEWER_GIT_RISKY) or (
        len(name) >= 3 and any(option.startswith(name) for option in REVIEWER_GIT_RISKY)
    )


def check_reviewer_git(argv: Command) -> None:
    if len(argv) < 2 or argv[1].startswith("-"):
        raise Refused("git with a global option (-c, -C, --config-env, …)")
    sub, args = argv[1], argv[2:]
    if sub == "branch" and args in ([], ["--show-current"], ["--list"]):
        return
    if sub not in REVIEWER_GIT:
        raise Refused(f"git {sub} isn't on the reviewers' read-only list")
    for a in args:
        if a.startswith("--") and risky_git_option(a):
            raise Refused(
                f"git {sub} {a} (writes, runs a program, reads outside git or lists ignored files)"
            )
        if sub == "ls-files" and short_group(a, "oi"):
            raise Refused("git ls-files listing ignored or untracked files")
        if not a.startswith("-") and (
            a.startswith(("/", "~")) or ".." in Path(a.split(":", 1)[-1]).parts
        ):
            # git diff quietly compares files outside the work tree (no-index mode)
            raise Refused(f"git {sub} on {a!r}, outside the repo")


def app_list_path() -> Path:
    return (
        Path(
            os.environ.get("APPOPSY_THIRD_PARTY_LIST", Path.home() / ".config/appopsy/my-apps.txt")
        )
        .expanduser()
        .resolve()
    )


def check_appopsy(argv: Command, cwd: Path, roots: Roots) -> None:
    """`uv run appopsy mask|redact-fixture --check`: files inside the repo only; the app
    list only as redact-fixture's --third-party-list."""
    sub, args = argv[3], argv[4:]
    if sub == "redact-fixture" and (
        "--check" not in args
        or any(a.startswith(("--out", "-o", "--mapping", "--force")) for a in args)
    ):
        raise Refused("redact-fixture other than --check")
    it = iter(args)
    for a in it:
        name, eq, value = a.partition("=") if a.startswith("--") else (a, "", "")
        if name == "--third-party-list":
            if sub != "redact-fixture":
                raise Refused("only redact-fixture --check may read the app list")
            listed = value if eq else next(it, "")
            if Path(listed).expanduser().resolve() != app_list_path():
                raise Refused("--third-party-list other than your app list")
        elif name == "--packages":
            target = value if eq else next(it, "")
            if not readable(target, cwd, roots):
                raise Refused(f"reading {target!r} (outside the repo, or in cases/ or reports/)")
        elif name == "--extra":
            if not eq:
                next(it, None)
        elif a.startswith("-"):
            continue
        elif not readable(a, cwd, roots):
            raise Refused(f"reading {a!r} (outside the repo, or in cases/ or reports/)")


def reviewer_check(command: str, roots: Roots) -> None:
    commands, targets, assignments = parse(command)
    for t in targets:
        if t != "/dev/null" and not t.isdigit():
            raise Refused(f"redirection into or from {t!r}")
    project = str(roots.project or "")
    cwd = roots.cwd
    for argv, assigned in zip(commands, assignments, strict=True):
        if any(not SAFE_ASSIGNMENT.match(a) for a in assigned):
            raise Refused("an environment assignment")
        if not argv:
            continue
        name = argv[0]  # exact: no paths, so `X+=/cat` or `./head` can't pass
        if name == "git":
            check_reviewer_git(argv)
        elif name in FILTERS:
            letters = FILTERS[name]
            for a in argv[1:]:
                if not re.fullmatch(rf"-[{letters}]+\d*|-\d+|\d+", a):
                    raise Refused(
                        f"{name} {a!r}: reviewers' filters only read a pipe (use the Read and "
                        "Grep tools for files)"
                    )
        elif name in BUILTINS:
            pass
        elif is_cmd(argv, "uv", "run", "appopsy") and argv[3:4] in (["mask"], ["redact-fixture"]):
            check_appopsy(argv, cwd, roots)
        elif is_cmd(argv, "uv", "run", "pytest"):
            check_tool(argv)
            args = [
                a for a in argv[3:] if not re.fullmatch(r"-r[a-zA-Z]+|-[qvxsl]+", a) or a == "-p"
            ]
            for flag, value in Flags(args, PYTEST_BOOL, PYTEST_VALUE).walk():
                if not flag and not readable(value or "", cwd, roots):
                    raise Refused("pytest on a path in cases/ or reports/")
        elif (
            name in ("python3", "python")
            and argv[1:2] == ["-I"]
            and argv[2:3] in ([GUARD_PATH], [f"{project}/{GUARD_PATH}"])
            and argv[3:] in ([], ["--reviewer"])
        ):
            pass  # probing this guard
        else:
            raise Refused(
                f"{name} isn't on the reviewers' Bash list (read files with the Read, Grep "
                "and Glob tools)"
            )


def reviewer_file_check(tool: str, tool_input: dict[str, object], roots: Roots) -> None:
    """A reviewer's Read, Grep or Glob call: inside the repo, never cases/ or reports/,
    and no recursive search from the root that holds them."""
    key = "file_path" if tool == "Read" else "path"
    target = tool_input.get(key)
    if target is None and tool != "Read":
        target = str(roots.cwd)  # Grep and Glob default to the working directory
    if not isinstance(target, str) or not readable(target, roots.cwd, roots):
        raise Refused(f"{tool} of {target!r} (outside the repo, or in cases/ or reports/)")
    pattern = tool_input.get("pattern") if tool == "Glob" else tool_input.get("glob")
    if isinstance(pattern, str):
        parts = Path(pattern).parts
        if (
            pattern.startswith(("/", "~"))
            or ".." in parts
            or set(pattern) & set("{}")
            or any(part.casefold() in PRIVATE_DIRS for part in parts)
        ):
            raise Refused(
                f"{tool} pattern {pattern!r} reaching outside the repo or into cases/ or reports/"
            )
    if tool in ("Grep", "Glob") and is_root(target, roots.cwd, roots):
        first = Path(pattern).parts[0] if isinstance(pattern, str) and pattern else "*"
        if tool == "Grep" or set(first) & set("*?["):
            raise Refused(
                f"{tool} across the repo root (it would reach cases/ and reports/); "
                "give a subdirectory as the path"
            )


REVIEWERS = {"privacy-reviewer", "report-reader", "allowlist-guard"}


def decide(mode: dict[str, bool]) -> str | None:
    """Why this tool call isn't routine (or, for a reviewer, isn't read-only)."""
    try:
        event = json.loads(sys.stdin.read())
    except ValueError:
        event = None
    if not isinstance(event, dict):
        return "a tool call this guard can't read"
    # Reviewer mode: wired in the agents' frontmatter (--reviewer), and also chosen
    # here from `agent_type`, because the settings.json hook runs inside subagents
    # too, while frontmatter hooks of project agents can be skipped (e.g. before
    # the workspace is trusted).
    if event.get("agent_type") in REVIEWERS:
        mode["reviewer"] = True
    tool = event.get("tool_name") or "Bash"
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return "a tool call this guard can't read"
    roots = Roots(os.environ.get("CLAUDE_PROJECT_DIR", ""), event.get("scratchpad_dir"),
                  event.get("cwd"))  # fmt: skip
    try:
        if tool in ("Read", "Grep", "Glob"):
            if mode["reviewer"]:
                reviewer_file_check(tool, tool_input, roots)
            return None
        command = tool_input.get("command")
        if not isinstance(command, str):
            return "a tool call this guard can't read"
        if mode["reviewer"]:
            reviewer_check(command, roots)
        else:
            main_check(command, roots)
    except Refused as e:
        return str(e)
    return None


def main() -> int:
    global DEADLINE
    DEADLINE = time.monotonic() + BUDGET_SECONDS
    mode = {"reviewer": "--reviewer" in sys.argv[1:]}
    try:
        reason = decide(mode)
    except Exception as e:  # fail closed: a crash must never mean "allowed"
        reason = f"the guard failed ({type(e).__name__}), so it can't vouch for this"
    if reason:
        reviewer = mode["reviewer"]
        out = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny" if reviewer else "ask",
                "permissionDecisionReason": (
                    f"{'Reviewers are read-only' if reviewer else 'Not a routine command'}: "
                    f"{reason}."
                ),
            }
        }
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
