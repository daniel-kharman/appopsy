"""Shared parser types and helpers."""

import re
from datetime import timedelta

from pydantic import BaseModel


class ParseWarning(BaseModel):
    """Something a parser saw but couldn't interpret. Recorded, never fatal."""

    source: str
    line: int | None = None
    text: str = ""
    message: str


# --- Shared helpers for dumpsys formats ---------------------------------------

_DURATION_PART = re.compile(r"(\d+)(ms|d|h|m|s)")
_DURATION_UNITS = {"d": "days", "h": "hours", "m": "minutes", "s": "seconds", "ms": "milliseconds"}
_UID_LABEL = re.compile(r"^u(?P<user>\d+)(?P<kind>[ais])(?P<n>\d+)$")
_LABEL_BASE = {"a": 10000, "i": 99000, "s": 20000}  # app, isolated, SDK sandbox


def parse_duration(text: str) -> timedelta | None:
    """``+1h2m3s4ms`` / ``-4m23s987ms`` -> timedelta (signed); None if not a duration."""
    sign = -1 if text.startswith("-") else 1
    body = text.lstrip("+-")
    parts = _DURATION_PART.findall(body)
    if not parts or "".join(n + u for n, u in parts) != body:
        return None
    return sign * timedelta(**{_DURATION_UNITS[u]: int(n) for n, u in parts})


def parse_uid_label(label: str) -> tuple[int, int, int] | None:
    """(uid, user_id, app_id) from ``u0a426`` or ``1000``; None if not recognised."""
    if label.isdigit():
        uid = int(label)
        return uid, uid // 100000, uid % 100000
    m = _UID_LABEL.match(label)
    if not m:
        return None
    user, app_id = int(m["user"]), _LABEL_BASE[m["kind"]] + int(m["n"])
    return user * 100000 + app_id, user, app_id
