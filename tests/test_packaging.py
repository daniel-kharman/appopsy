"""The built wheel carries what an installed appopsy needs: rule specs, templates."""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from appopsy.rules.engine import RULES_DIR

ROOT = Path(__file__).resolve().parent.parent
UV = shutil.which("uv")


@pytest.mark.skipif(UV is None, reason="needs uv to build the wheel")
def test_wheel_includes_rule_specs_and_templates(tmp_path: Path) -> None:
    assert UV is not None
    subprocess.run(
        [UV, "build", "--wheel", "--quiet", "--out-dir", str(tmp_path), str(ROOT)],
        check=True,
        timeout=300,
    )
    (wheel,) = tmp_path.glob("appopsy-*.whl")
    names = set(zipfile.ZipFile(wheel).namelist())
    specs = {
        f"appopsy/rules/specs/{pack}/{f.name}"
        for pack in ("privacy", "security")
        for f in (RULES_DIR / pack).iterdir()
    }
    assert specs and specs <= names, sorted(specs - names)
    assert any(n.endswith(".yaml") for n in specs)
    assert "appopsy/report/templates/report.md.j2" in names
    assert "appopsy/report/app_names.tsv" in names
