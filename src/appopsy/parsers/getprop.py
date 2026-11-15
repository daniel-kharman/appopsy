"""Parser for `getprop` output: ``[key]: [value]`` lines.

Values can span lines (e.g. ``persist.sys.boot.reason.history``): the opening
``[`` is on the key's line and the closing ``]`` ends a later line.
"""

from __future__ import annotations

import re
from datetime import date

from pydantic import BaseModel

from appopsy.parsers.base import ParseWarning

SOURCE = "getprop"

_PROP = re.compile(r"^\[(?P<key>[^\]]+)\]: \[(?P<rest>.*)$")


def parse_getprop(text: str) -> tuple[dict[str, str], list[ParseWarning]]:
    props: dict[str, str] = {}
    warnings: list[ParseWarning] = []
    pending: tuple[str, int, list[str]] | None = None  # key, start line, value lines

    def unclosed(key: str, lineno: int) -> None:
        warnings.append(
            ParseWarning(source=SOURCE, line=lineno, text=key, message="value never closed")
        )

    for lineno, line in enumerate(text.splitlines(), start=1):
        m = _PROP.match(line)
        if m:
            if pending:
                unclosed(pending[0], pending[1])
                pending = None
            key, rest = m.group("key"), m.group("rest")
            if rest.endswith("]"):
                props[key] = rest[:-1]
            else:
                pending = (key, lineno, [rest])
        elif pending:
            key, _, parts = pending
            if line.endswith("]"):
                props[key] = "\n".join([*parts, line[:-1]])
                pending = None
            else:
                parts.append(line)
        elif line.strip():
            warnings.append(
                ParseWarning(source=SOURCE, line=lineno, text=line, message="not a property line")
            )
    if pending:
        unclosed(pending[0], pending[1])
    return props, warnings


class DeviceInfo(BaseModel):
    manufacturer: str | None = None
    model: str | None = None
    device: str | None = None
    android_release: str | None = None
    sdk: int | None = None
    security_patch: date | None = None
    build_fingerprint: str | None = None
    timezone: str | None = None


def _get(props: dict[str, str], key: str) -> str | None:
    return props.get(key, "").strip() or None


def device_info(props: dict[str, str]) -> DeviceInfo:
    sdk = _get(props, "ro.build.version.sdk")
    patch = _get(props, "ro.build.version.security_patch")
    try:
        patch_date = date.fromisoformat(patch) if patch else None
    except ValueError:
        patch_date = None
    return DeviceInfo(
        manufacturer=_get(props, "ro.product.manufacturer"),
        model=_get(props, "ro.product.model"),
        device=_get(props, "ro.product.device"),
        android_release=_get(props, "ro.build.version.release"),
        sdk=int(sdk) if sdk and sdk.isdigit() else None,
        security_patch=patch_date,
        build_fingerprint=_get(props, "ro.build.fingerprint"),
        timezone=_get(props, "persist.sys.timezone"),
    )
