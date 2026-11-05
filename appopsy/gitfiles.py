"""Which files in a folder git tracks or could commit, for the third-party checks.

Besides appopsy/adb.py, this is the only module that starts a process, and it runs
exactly one read-only command with a fixed argument list:
`git -C <folder> ls-files -co --exclude-standard -z`. Ignored paths (a local
`cases/` folder, `.venv/`) are left out, so the owner's own case data doesn't fail
a check that is about what could reach the repository.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ARGS = ("ls-files", "-co", "--exclude-standard", "-z")


def committable(root: Path) -> list[Path] | None:
    """Files under ``root`` that git tracks or could commit (not ignored), sorted;
    None if ``root`` isn't in a git work tree or git isn't installed."""
    git = shutil.which("git")
    if git is None:
        return None
    try:
        result = subprocess.run(  # fixed argument list, see the module docstring
            [git, "-C", str(root), *ARGS], capture_output=True, check=True, timeout=60
        )
    except (OSError, subprocess.SubprocessError):
        return None
    names = result.stdout.decode("utf-8", errors="surrogateescape").split("\0")
    # -c also lists tracked files deleted from the work tree.
    return sorted(p for name in names if name and (p := root / name).is_file())
