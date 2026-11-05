"""Case folders: where one audit's raw output, parsed data and report live.

Layout::

    cases/<YYYYmmddTHHMMSSZ>-<model>/
        manifest.json   # what was run, when (host UTC), and whether it worked
        raw/            # command output saved verbatim, one file per command
        parsed/         # parser output (JSON)

Case folders contain personal data. They are gitignored, and are created
readable by the current user only.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from appopsy import __version__

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


def slugify(text: str | None) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return slug[:40] or "device"


def raw_filename(command: Sequence[str]) -> str:
    """Default raw file name: ``dumpsys package com.x`` -> ``dumpsys_package_com.x.txt``."""
    stem = "_".join(command)
    return re.sub(r"[^A-Za-z0-9._-]+", "-", stem).strip("-") + ".txt"


class CommandRecord(BaseModel):
    command: list[str]
    file: str | None = None  # relative to raw/
    started: datetime
    finished: datetime
    ok: bool
    error: str | None = None
    bytes: int = 0


class Manifest(BaseModel):
    appopsy_version: str = __version__
    created: datetime
    serial: str
    model: str | None = None
    commands: list[CommandRecord] = Field(default_factory=list)


class Case:
    def __init__(self, root: Path, manifest: Manifest, clock: Clock = utc_now) -> None:
        self.root = root
        self.manifest = manifest
        self.clock = clock

    @property
    def raw(self) -> Path:
        return self.root / "raw"

    @property
    def parsed(self) -> Path:
        return self.root / "parsed"

    @classmethod
    def create(
        cls,
        cases_dir: Path,
        *,
        serial: str,
        model: str | None,
        clock: Clock = utc_now,
    ) -> Case:
        created = clock()
        base = f"{created:%Y%m%dT%H%M%SZ}-{slugify(model)}"
        cases_dir.mkdir(parents=True, exist_ok=True)
        root = cases_dir / base
        n = 1
        while True:
            try:
                root.mkdir(mode=0o700)
                break
            except FileExistsError:
                n += 1
                root = cases_dir / f"{base}-{n}"
        for sub in ("raw", "parsed"):
            (root / sub).mkdir(mode=0o700)
        case = cls(root, Manifest(created=created, serial=serial, model=model), clock)
        case.save()
        return case

    def _write_private(self, path: Path, text: str) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)

    def _unique_raw_name(self, name: str) -> str:
        taken = {c.file for c in self.manifest.commands}
        if name not in taken and not (self.raw / name).exists():
            return name
        stem, dot, ext = name.rpartition(".")
        stem, ext = (stem, f"{dot}{ext}") if dot else (name, "")
        n = 2
        while f"{stem}-{n}{ext}" in taken or (self.raw / f"{stem}-{n}{ext}").exists():
            n += 1
        return f"{stem}-{n}{ext}"

    def write_raw(
        self,
        command: Sequence[str],
        output: str,
        *,
        started: datetime,
        finished: datetime,
        name: str | None = None,
    ) -> Path:
        """Save a command's output verbatim and record it in the manifest."""
        filename = self._unique_raw_name(name or raw_filename(command))
        path = self.raw / filename
        self._write_private(path, output)
        self.manifest.commands.append(
            CommandRecord(
                command=list(command),
                file=filename,
                started=started,
                finished=finished,
                ok=True,
                bytes=len(output.encode("utf-8")),
            )
        )
        self.save()
        return path

    def record_failure(
        self, command: Sequence[str], error: str, *, started: datetime, finished: datetime
    ) -> None:
        self.manifest.commands.append(
            CommandRecord(
                command=list(command), started=started, finished=finished, ok=False, error=error
            )
        )
        self.save()

    def save(self) -> None:
        tmp = self.root / "manifest.json.tmp"
        self._write_private(tmp, self.manifest.model_dump_json(indent=2) + "\n")
        tmp.replace(self.root / "manifest.json")

    @classmethod
    def load(cls, root: Path) -> Case:
        data = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        return cls(root, Manifest.model_validate(data))
