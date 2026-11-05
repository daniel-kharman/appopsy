"""Guards principle 1: nothing outside appopsy/adb.py may spawn processes."""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "appopsy"
FORBIDDEN_MODULES = {"subprocess", "pty", "multiprocessing"}
# os functions that start processes.
FORBIDDEN_OS = {
    "system", "popen", "spawnl", "spawnle", "spawnlp", "spawnv", "spawnve", "spawnvp",
    "execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe", "fork", "forkpty",
    "posix_spawn", "posix_spawnp",
}  # fmt: skip


def _offences(tree: ast.AST) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [(node.lineno, a.name) for a in node.names
                      if a.name.split(".")[0] in FORBIDDEN_MODULES or a.name == "asyncio.subprocess"]  # fmt: skip
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = {a.name for a in node.names}
            if module.split(".")[0] in FORBIDDEN_MODULES or module == "asyncio.subprocess":
                found.append((node.lineno, module))
            elif module == "os" and names & FORBIDDEN_OS:
                found.append(
                    (node.lineno, f"from os import {', '.join(sorted(names & FORBIDDEN_OS))}")
                )
            elif module == "asyncio" and "subprocess" in names:
                found.append((node.lineno, "from asyncio import subprocess"))
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "os" and node.attr in FORBIDDEN_OS:
                found.append((node.lineno, f"os.{node.attr}"))
            elif node.value.id == "asyncio" and node.attr.startswith("create_subprocess"):
                found.append((node.lineno, f"asyncio.{node.attr}"))
    return found


# The one exemption besides the adb wrapper: gitfiles.py, which may only run
# `git -C <folder> ls-files -co --exclude-standard -z` (checked below).
EXEMPT = {PACKAGE / "adb.py", PACKAGE / "gitfiles.py"}


def test_only_adb_wrapper_spawns_processes() -> None:
    offenders = [
        f"{path.relative_to(PACKAGE.parent)}:{line} {what}"
        for path in PACKAGE.rglob("*.py")
        if path not in EXEMPT
        for line, what in _offences(ast.parse(path.read_text(), filename=str(path)))
    ]
    assert offenders == [], f"process spawning outside appopsy/adb.py: {offenders}"


def test_gitfiles_runs_only_its_one_read_only_command() -> None:
    from appopsy import gitfiles

    assert gitfiles.ARGS == ("ls-files", "-co", "--exclude-standard", "-z")
    tree = ast.parse((PACKAGE / "gitfiles.py").read_text())
    calls = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name) and n.func.value.id == "subprocess"
    ]  # fmt: skip
    assert [c.func.attr for c in calls] == ["run"]  # type: ignore[attr-defined]
    argv = ast.unparse(calls[0].args[0])
    assert argv == "[git, '-C', str(root), *ARGS]"
    assert [(line, what) for line, what in _offences(tree) if what != "subprocess"] == []


def test_guard_detects_spawning() -> None:
    code = """
import subprocess
from subprocess import run
import os
from os import system
os.system("x")
os.execv("x", [])
import asyncio
asyncio.create_subprocess_exec("x")
self.system = set()
"""
    lines = {line for line, _ in _offences(ast.parse(code))}
    assert lines == {2, 3, 5, 6, 7, 9}  # not line 10: an attribute named `system` is fine
