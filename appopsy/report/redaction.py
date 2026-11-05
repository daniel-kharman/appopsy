"""`--redact`: a copy of the report that can be shared.

Apps that aren't public knowledge (anything but system packages and the apps in
the bundled name map) are shown as "Unlisted app <id>". The id is an HMAC of the
package name under a key made fresh for every render: a plain hash could be
reversed by hashing a list of popular apps, and a fresh key means two shared
reports can't be linked. Job, alarm and location-request names of those apps are
hidden too, since they usually contain the app's name (except names a public app in
the same report also shows, such as library workers: those identify nothing).

Times become days relative to collection ("today", "3 days ago"): exact times show
when the phone was used.

The rendered text is checked before it's written: no private package name, no
hidden name, no device identifier and no exact time may be left. A failed check
refuses.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field

from appopsy.labels import short_class
from appopsy.redact import identifiers
from appopsy.rules.case import CaseData
from appopsy.rules.engine import Finding

HIDDEN = "(hidden)"
# A date with a time of day says when the phone was used; redacted copies show days
# relative to collection instead. Dates alone (the security patch) are fine.
_EXACT_TIME = re.compile(r"\b\d{4}-\d\d-\d\d[ T]\d\d:\d\d")
# Table columns whose cells name things inside an app (see build._tables).
HIDDEN_COLUMNS = frozenset({"Job", "Alarm", "Requested as"})


class RedactionError(Exception):
    """The redacted report still contained something it must not; nothing was written."""


@dataclass
class Redaction:
    aliases: dict[str, str]  # private package -> "Unlisted app 3f2a9c"
    hidden: set[str] = field(default_factory=set)  # strings that must not be in the text

    def is_private(self, package: str | None) -> bool:
        return package is not None and package in self.aliases


def _alias(key: bytes, package: str) -> str:
    digest = hmac.new(key, package.encode(), hashlib.sha256).hexdigest()
    return f"Unlisted app {digest[:6]}"


def _inner_names(f: Finding) -> Iterable[str]:
    """Names inside an app that a finding's facts carry: jobs, alarm tags, request tags."""
    for job in f.facts.get("jobs", []):
        yield str(job["what"])
        yield short_class(str(job["what"]))
    for alarm in f.facts.get("top_alarms", []):
        yield str(alarm["tag"])
    for request in f.facts.get("requests", []):
        if request.get("tag"):
            yield str(request["tag"])


def plan(
    case: CaseData, findings: list[Finding], public: set[str], key: bytes | None = None
) -> Redaction:
    """Which packages to alias and which strings to keep out of the redacted text.

    ``public``: package names that may be shown (system packages, the name map).
    """
    key = key or secrets.token_bytes(32)
    shown = {f.package for f in findings if f.package}
    installers = {i for i in case.installers.values() if i}
    private = sorted((case.third_party | shown | installers) - public - case.system - {"android"})
    redaction = Redaction({p: _alias(key, p) for p in private})
    redaction.hidden |= set(private)
    # A name a public app in the same report also uses (library workers such as
    # GnpWorker or SyncJobService) says nothing about which unlisted app has it.
    # Short names like "Sync" would match ordinary words: only distinctive ones count.
    shared = {n for f in findings if not redaction.is_private(f.package) for n in _inner_names(f)}
    for f in findings:
        if redaction.is_private(f.package):
            redaction.hidden |= {n for n in _inner_names(f) if len(n) >= 8 and n not in shared}
    return redaction


def _whole(name: str) -> re.Pattern[str]:
    """``name`` as a whole name, not inside a longer one (AnalyticsWorker is not in
    NotificationAnalyticsWorker; com.example.bank is not in com.example.banking)."""
    return re.compile(rf"(?<![\w.$]){re.escape(name)}(?![\w$])")


def check(text: str, redaction: Redaction) -> None:
    """Refuse a redacted report that still names a private app or holds an identifier.

    The message gives counts only, so the error itself can be shared or logged.
    """
    left = sum(1 for name in redaction.hidden if _whole(name).search(text))
    found = identifiers(text)
    times = len(_EXACT_TIME.findall(text))
    if left or found or times:
        kinds = sorted({f.category for f in found})
        raise RedactionError(
            f"redacted report not written: {left} private name(s), {len(found)} "
            f"identifier(s) ({', '.join(kinds) or 'none'}) and {times} exact time(s) "
            "were left in it"
        )
