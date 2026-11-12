#!/usr/bin/env python3
"""PreToolUse hook: only GET `gh api` calls run without a prompt.

.claude/settings.json pre-approves `gh api *` so that read-only audits (repo
settings, rulesets, check runs) don't need the maintainer. A permission rule
can't tell GET from POST, so this hook reads the command and answers "ask" for
anything that isn't plainly a GET:

- an explicit method other than GET (`-X POST`, `--method=PATCH`, `-XDELETE`);
- request fields or a body without `-X GET` (`-f`, `-F`, `--field`,
  `--raw-field`, `--input`), which make gh send a POST;
- any `gh api` this parser can't follow (inside quotes, `sh -c`, `$(...)`, or a
  command shlex can't split).

It never allows anything itself (a hook "allow" can't override deny/ask rules
anyway); it only turns an otherwise pre-approved call into a prompt. Standard
library only, so it runs with any python3.
"""

from __future__ import annotations

import json
import re
import shlex
import sys

CONTROL = {";", "&&", "||", "|", "|&", "&", "(", ")", "\n"}
FIELD_FLAGS = ("--field", "--raw-field", "--input")
GH_API_TEXT = re.compile(r"\bgh\b\s+api\b")


def _invocations(tokens: list[str]) -> list[list[str]]:
    """The argument lists that follow each `gh api` in the token stream."""
    found: list[list[str]] = []
    for i, tok in enumerate(tokens[:-1]):
        if (tok == "gh" or tok.endswith("/gh")) and tokens[i + 1] == "api":
            args: list[str] = []
            for t in tokens[i + 2 :]:
                if t in CONTROL:
                    break
                args.append(t)
            found.append(args)
    return found


def _non_get_reason(args: list[str]) -> str | None:
    method: str | None = None
    sends_fields = False
    it = iter(args)
    for a in it:
        if a in ("-X", "--method"):
            method = next(it, "").upper()
        elif a.startswith("--method="):
            method = a.split("=", 1)[1].upper()
        elif a.startswith("-X") and len(a) > 2:
            method = a[2:].upper()
        elif a in ("-f", "-F") or a in FIELD_FLAGS:
            sends_fields = True
            next(it, None)
        elif a.startswith(tuple(f + "=" for f in FIELD_FLAGS)) or (
            len(a) > 2 and a[:2] in ("-f", "-F") and not a.startswith("--")
        ):
            sends_fields = True
    if method is not None and method != "GET":
        return f"gh api with method {method or '(missing)'}"
    if method is None and sends_fields:
        return "gh api with request fields or a body (gh sends these as POST)"
    return None


def decide(command: str) -> str | None:
    """Why this command needs a prompt, or None if every `gh api` in it is a GET."""
    if not GH_API_TEXT.search(command):
        return None
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return "gh api in a command that can't be parsed"
    calls = _invocations(tokens)
    if len(calls) != len(GH_API_TEXT.findall(command)):
        return "gh api inside quotes, a subshell or another command; can't confirm it is a GET"
    for args in calls:
        reason = _non_get_reason(args)
        if reason:
            return reason
    return None


def main() -> int:
    try:
        event = json.load(sys.stdin)
        command = event.get("tool_input", {}).get("command", "")
    except (ValueError, AttributeError):
        return 0  # not a Bash event we understand; normal permission rules apply
    if not isinstance(command, str):
        return 0
    reason = decide(command)
    if reason:
        out = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": f"Not a read-only gh api call: {reason}.",
            }
        }
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
