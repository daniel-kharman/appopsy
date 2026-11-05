"""Third-party package policy for fixtures.

The list of apps on a phone says a lot about its owner, so fixtures follow a
closed policy: system packages are kept as they are, and the only third-party
packages that may appear are a fixed, public allowlist (``DEFAULT_ALLOWLIST``,
or your own via ``redact-fixture --packages``). A redacted fixture looks like a
phone with exactly those third-party apps installed.

Redaction:

- ``pm list packages`` output: lines for packages that are neither system nor
  allowlisted are dropped; allowlisted entries that are missing are added in the
  same line format (so the synthetic sideloaded app always appears in a
  third-party listing).
- Structural positions in dumpsys output (the ``Queries:`` section,
  ``queriesPackages=[...]``, installer fields, ``Package [x]``, data and APK
  paths): list elements naming a non-allowed package are dropped; other lines
  naming one are removed, with their indented children if they are a header.
- Any line mentioning a known third-party package (from ``pm list`` output in the
  same input set) that isn't allowlisted is removed.

Scanning (CI): the structural positions above may only name system or
allowlisted packages. The system set comes from ``pm-list-packages-system.txt``
files in the scanned tree, so package fixtures must include that list.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from appopsy.parsers.packages import SYSTEM_LIST_FILENAME


@dataclass(frozen=True)
class AllowedPackage:
    name: str
    installer: str = "com.android.vending"


SYNTHETIC_SIDELOADED = "com.example.sideloaded"

DEFAULT_ALLOWLIST: tuple[AllowedPackage, ...] = (
    AllowedPackage("com.twitter.android"),
    AllowedPackage("com.facebook.katana"),
    AllowedPackage("com.facebook.orca"),
    AllowedPackage("com.whatsapp"),
    AllowedPackage("com.tencent.mm"),
    # Synthetic, installed from an APK via the system package installer (not Play).
    AllowedPackage(SYNTHETIC_SIDELOADED, "com.google.android.packageinstaller"),
)

_PKG = r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*"
_PKG_RE = re.compile(_PKG)
_PM_LINE = re.compile(rf"^package:(?:(?P<path>\S+)=)?(?P<name>{_PKG})(?P<rest>.*)$")
_PM_INSTALLER = re.compile(r"(?<=installer=)\S+")
_PM_UID = re.compile(r"(?<=uid:)\d+")
# Package lists: an app's declared queries, and appops restriction exceptions
# (apps allowed through Do Not Disturb).
_QUERIES_LIST = re.compile(
    r"(?P<pre>\bqueriesPackages=\[|\bexceptions: \[)(?P<list>[^\]]*)(?P<post>\])"
)
# Single package references whose position makes them unambiguous.
_SINGLE_REF = re.compile(
    r"(?:\bPackage \[|\bpkg=Package\{[0-9a-f]+ |\bPackageSetting\{[0-9a-f]+ "
    # dumpsys appops: proxied access, and rows of the "Last 1 Hour" UID|PACKAGE_NAME|... table
    r"|\bproxy\[uid=\d+, pkg=|^\d+\||^    Package (?!\[)"
    r"|\b(?:installerPackageName|installInitiatingPackageName|installOriginatingPackageName"
    r"|updateOwnerPackageName|sourcePackage)="
    r"|\bdataDir=/data/(?:user(?:_de)?/\d+|data)/|/data/app/~~[^/\s]*/"
    # dumpsys jobscheduler: job source/service, WorkManager tags (#Worker#@ns@pkg/),
    # plain job headers, per-app stats, quota keys, components, "from <uid>: pkg"
    r"|\bSource: uid=\S+ user=\d+ pkg=|\bService: |#@[\w.]+@"
    r"|\bJOB (?:[\w.]+:)?#?[\w.:]+/-?\d+: [0-9a-f]+ (?=[A-Za-z])"
    r"|\bu\d+[a-z]\d+ / |<\d+>|ComponentInfo\{|ComponentInfo\{[^}]*\}: "
    r"|\bfrom (?:u\d+[a-z]\d+|\d+)(?: [a-z][a-z, ]*)?: |\bTrace tag: \S*?#"
    # dumpsys alarm: pending-intent owner, alarm owner, per-app wakeup stats
    r"|PendingIntentRecord\{[0-9a-f]+ |\bwhenElapsed -?\d+ |\bu\d+[a-z]\d+:(?=[A-Za-z]))"
    rf"(?P<pkg>{_PKG})"
)
# Line-anchored positions that don't fit the prefix form above.
_LINE_REFS: tuple[re.Pattern[str], ...] = (
    re.compile(rf"^\s+(?P<pkg>{_PKG}), u\d+: "),  # alarm: last deliveries per package
    re.compile(rf"^\s+\d+:(?P<pkg>{_PKG})="),  # jobscheduler: per-UID package flags
    re.compile(rf"^\s+\d+/(?P<pkg>{_PKG}): \{{"),  # jobscheduler: per-app execution stats
    re.compile(rf"^\s+\d{{4,6}}/(?P<pkg>{_PKG})(?:\[[^\]]*\])?: "),  # location: per-app aggregates
    re.compile(rf"^    (?P<pkg>{_PKG})/[\w.$]+$"),  # launcher query: an activity's component
)
# location: bare package lines under the allow/deny lists in "Location Settings:"
# (only inside that block; elsewhere a bare dotted line can be a domain name).
_SETTINGS_PKG = re.compile(rf"^\s+(?P<pkg>{_PKG})(?:\[[^\]]*\])?\s*$")  # [*], [tag]


def _location_settings_lines(lines: list[str]) -> list[int]:
    """Indexes of bare package lines inside the "Location Settings:" block."""
    hits: list[int] = []
    inside: int | None = None
    for i, raw in enumerate(lines):
        line = raw.rstrip("\n")
        indent = len(line) - len(line.lstrip())
        if line.strip() == "Location Settings:":
            inside = indent
            continue
        if inside is not None and line.strip() and indent <= inside:
            inside = None
        if inside is not None and _SETTINGS_PKG.match(line) and "." in line:
            hits.append(i)
    return hits


# location: "<uid>/<pkg>[tag]/<id>" in registrations and deliveries.
_UID_SLASH_PKG = re.compile(rf"(?<![\w/])\d{{4,6}}/(?P<pkg>{_PKG})(?=[\[/:\s]|$)")
# location: WorkSource{<uid> <pkg>, <uid> <pkg> <tag>, ...}, filtered element by element.
_WORKSOURCE = re.compile(r"(?P<pre>WorkSource\{)(?P<list>[^}]*)(?P<post>\})")
# jobscheduler "Cached UID->package map": `10123: {a, b, c}`, filtered like a list.
_BRACE_LIST = re.compile(r"^(?P<pre>\s+\d+: \{)(?P<list>[^}]*)(?P<post>\})$")
# jobscheduler "Recently completed jobs": entries headed by a relative time, with the
# job's lines as siblings, so an entry goes whole if any of its lines isn't allowed.
_RECENT_HEADER = re.compile(r"^  [+-](?:\d+(?:ms|[dhms]))+$")
# A block owned by a bare UID (alarm history: `    u0a418:` then entries whose tags
# needn't name the package). Kept only if the capture shows every package of that
# UID is system or allowlisted; an unknown UID counts as not allowed.
_UID_ONLY_HEADER = re.compile(r"^\s+(?P<label>u\d+[a-z]\d+):\s*$")
_UID_LABEL = re.compile(r"^u(?P<user>\d+)(?P<kind>[a-z])(?P<n>\d+)$")
# Where a capture says which packages a UID (app id) has.
_APPID_HARVEST = (
    re.compile(r"^  Package \[(?P<pkg>[^\]]+)\][^\n]*\n    appId=(?P<appid>\d+)", re.M),
    re.compile(
        r"^  SharedUser \[[^\]]+\][^\n]*\n    appId=(?P<appid>\d+)\n    Packages\n"
        r"(?P<members>(?:      PackageSetting\{[^\n]*\n)+)",
        re.M,
    ),
    re.compile(r"^\s+(?P<appid>\d{4,6}): \{(?P<list>[^}]*)\}$", re.M),  # jobscheduler UID map
)
_APPOPS_UID_BLOCK = re.compile(r"^  Uid (?P<label>\S+):\n(?P<body>(?:(?:    |\n).*\n?)*)", re.M)


def _worksource_packages(body: str) -> list[str]:
    return [m.group(1) for m in re.finditer(rf"(?:^|,\s*)\d+ ({_PKG})", body)]


def _refs(line: str) -> list[str]:
    """Packages named at structural positions on one line."""
    found = [m["pkg"] for m in _SINGLE_REF.finditer(line)]
    found += [m["pkg"] for rx in _LINE_REFS if (m := rx.match(line))]
    found += [m["pkg"] for m in _UID_SLASH_PKG.finditer(line)]
    for m in _WORKSOURCE.finditer(line):
        found += _worksource_packages(m["list"])
    # Package names have a dot; a single word in one of these positions ("Delay" in
    # "from u0a426: Delay=...") isn't one. `android` is the exception.
    return [p for p in found if "." in p or p == "android"]


# Blocks that belong to one owner and list its member packages. If any member
# isn't allowed, the whole block goes: the rest of it (a vendor-named shared user,
# vendor permission names, per-op history) still points at the owner.
# `dumpsys package shared-users`: one entry per shared UID.
_SHARED_USER_HEADER = re.compile(r"^  SharedUser \[(?P<name>[^\]]+)\] \([0-9a-f]+\):$")
_PACKAGE_SETTING = re.compile(rf"\bPackageSetting\{{[0-9a-f]+ (?P<pkg>{_PKG})/\d+\}}")
# `dumpsys appops`: one block per UID (`u0a426` or `1000`) with `Package <pkg>:` members.
_UID_HEADER = re.compile(r"^  Uid (?P<name>u\d+[a-z]\d+|\d+):$")
_UID_MEMBER = re.compile(rf"^    Package (?P<pkg>{_PKG}):$")


def _owner_blocks(
    lines: list[str], header: re.Pattern[str], member: re.Pattern[str]
) -> list[tuple[int, int, str, list[str]]]:
    """(start, end, block name, member packages) for each block opened by ``header``."""
    entries: list[tuple[int, int, str, list[str]]] = []
    i = 0
    while i < len(lines):
        m = header.match(lines[i].rstrip("\n"))
        if not m:
            i += 1
            continue
        end = i + 1
        while end < len(lines) and (not lines[end].strip() or _indent(lines[end]) > 2):
            end += 1
        members = [mm["pkg"] for line in lines[i:end] for mm in member.finditer(line.rstrip("\n"))]
        entries.append((i, end, m["name"], members))
        i = end
    return entries


# launcher query: one `Activity #N:` block per launcher activity.
_ACTIVITY_HEADER = re.compile(r"^  Activity #(?P<name>\d+):$")
_ACTIVITY_COMPONENT = re.compile(rf"^    (?P<pkg>{_PKG})/[\w.$]+$")


def _shared_user_entries(lines: list[str]) -> list[tuple[int, int, str, list[str]]]:
    return _owner_blocks(lines, _SHARED_USER_HEADER, _PACKAGE_SETTING)


def _uid_blocks(lines: list[str]) -> list[tuple[int, int, str, list[str]]]:
    return _owner_blocks(lines, _UID_HEADER, _UID_MEMBER)


def _app_id(label: str) -> int | None:
    """App id for `u0a426` (10426) or `1000`; None for kinds whose numbering isn't known."""
    if label.isdigit():
        return int(label) % 100000
    m = _UID_LABEL.match(label)
    if not m or m["kind"] != "a":
        return None
    return 10000 + int(m["n"])


def load_allowlist(path: Path) -> tuple[AllowedPackage, ...]:
    """Read ``name [installer]`` lines; ``#`` starts a comment."""
    entries: list[AllowedPackage] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        parts = raw.split("#", 1)[0].split()
        if not parts:
            continue
        if not all(_PKG_RE.fullmatch(p) for p in parts) or len(parts) > 2:
            raise ValueError(f"Bad allowlist line: {raw!r} (expected 'package [installer]')")
        entries.append(AllowedPackage(*parts))
    return tuple(entries)


def load_third_party_list(path: Path) -> set[str]:
    """Read a list of your own installed apps: ``pm list packages -3`` output or bare names.

    This list is personal. Keep it outside the repository (e.g.
    ``~/.config/appopsy/my-apps.txt``); :func:`check_outside_repo` enforces that.
    """
    names: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("package:"):
            m = _PM_LINE.match(line)
            name = m["name"] if m else ""
        else:
            name = line if len(line.split()) == 1 else ""
        # Third-party package names always have at least two segments.
        if not (_PKG_RE.fullmatch(name) and "." in name):
            raise ValueError(f"Bad third-party list line: {raw!r}")
        names.add(name)
    return names


DEFAULT_THIRD_PARTY_LIST = Path.home() / ".config" / "appopsy" / "my-apps.txt"
# Characters that can be part of one token around a package name: class names,
# component paths, intent actions, WorkManager tags (`#W#@ns@pkg/x.Service`).
_NAME_CHARS = r"[\w./$:@#*+-]"
# Before the name only name-like characters, so `tag=*walarm*:` stays readable while
# `ACTION.` prefixes and `#Worker#@ns@` tags are still masked.
_NAME_PREFIX_CHARS = r"[\w./$@#-]"


def mask_apps(text: str, names: Iterable[str], allowed: Iterable[str] = ()) -> str:
    """Replace every token that contains one of ``names`` with ``<app>``.

    For looking at raw captures: the whole token goes, so neither the package nor a
    class name or action attached to it (``.../com.vendor.app/.service.X``,
    ``ACTION.com.vendor.app.Sync``) is printed. Allowlisted names are not masked.
    """
    keep = set(allowed)
    targets = sorted((n for n in names if n not in keep), key=len, reverse=True)
    if not targets:
        return text
    pattern = re.compile(
        rf"{_NAME_PREFIX_CHARS}*?(?<![A-Za-z0-9_])(?:{'|'.join(map(re.escape, targets))})"
        rf"(?![A-Za-z0-9_]){_NAME_CHARS}*"
    )
    return pattern.sub("<app>", text)


def check_outside_repo(path: Path) -> None:
    """Refuse a personal list that sits inside a git working tree."""
    for parent in path.resolve().parents:
        if (parent / ".git").exists():
            raise ValueError(
                f"{path} is inside the git working tree at {parent}. Keep your app list "
                "outside the repository, e.g. ~/.config/appopsy/my-apps.txt."
            )


def is_pm_list(text: str) -> bool:
    lines = [line for line in text.splitlines() if line.strip()]
    return bool(lines) and all(line.startswith("package:") for line in lines)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


@dataclass
class PackagePolicy:
    allowlist: tuple[AllowedPackage, ...] = DEFAULT_ALLOWLIST
    system: set[str] = field(default_factory=set)
    listed: set[str] = field(default_factory=set)  # every package seen in pm list output
    uid_packages: dict[int, set[str]] = field(default_factory=dict)  # app id -> packages
    removed: int = 0

    @property
    def allowed(self) -> dict[str, AllowedPackage]:
        return {a.name: a for a in self.allowlist}

    @property
    def system_known(self) -> bool:
        return bool(self.system)

    def ok(self, pkg: str) -> bool:
        # "null" is how dumpsys prints an absent installer, not a package.
        return pkg == "null" or pkg in self.system or pkg in self.allowed

    def _harvest_uids(self, text: str) -> None:
        def add(appid: int, pkgs: Iterable[str]) -> None:
            self.uid_packages.setdefault(appid, set()).update(p for p in pkgs if p)

        for m in _APPID_HARVEST[0].finditer(text):
            add(int(m["appid"]), [m["pkg"]])
        for m in _APPID_HARVEST[1].finditer(text):
            add(int(m["appid"]), re.findall(r"PackageSetting\{[0-9a-f]+ ([\w.]+)/", m["members"]))
        for m in _APPID_HARVEST[2].finditer(text):
            add(int(m["appid"]) % 100000, [x.strip() for x in m["list"].split(",")])
        if "\n  Uid " in text:
            for m in _APPOPS_UID_BLOCK.finditer(text):
                appid = _app_id(m["label"])
                if appid is not None:
                    add(appid, re.findall(r"(?m)^    Package ([\w.]+):$", m["body"]))

    def uid_ok(self, label: str) -> bool:
        """True if every package the capture shows for this UID is allowed."""
        appid = _app_id(label)
        if appid is None:
            return False
        if appid < 10000:  # system UIDs (1000 system, 1001 radio, ...)
            return True
        pkgs = self.uid_packages.get(appid, set())
        return bool(pkgs) and all(self.ok(p) for p in pkgs)

    def harvest(self, name: str, text: str) -> None:
        self._harvest_uids(text)
        if not is_pm_list(text):
            return
        names = {m["name"] for line in text.splitlines() if (m := _PM_LINE.match(line))}
        if name == SYSTEM_LIST_FILENAME:
            self.system |= names
        self.listed |= names

    # --- shared structural checks ------------------------------------------

    def _filter_list(self, body: str) -> tuple[str, list[str]]:
        """Filter a comma-separated package list; return (new body, removed)."""
        sep = ", " if ", " in body else ","
        items = [i.strip() for i in body.split(",") if i.strip()]
        keep = [i for i in items if self.ok(i)]
        return sep.join(keep), [i for i in items if not self.ok(i)]

    def _queries_entry(self, stripped: str) -> tuple[str, list[str]] | None:
        """For a Queries-section line, return (kind, packages) if it names packages."""
        body = stripped.removesuffix(":")
        if body.startswith("[") and body.endswith("]"):
            return "list", [i.strip() for i in body[1:-1].split(",") if i.strip()]
        if _PKG_RE.fullmatch(body) and ("." in body or body in self.system):
            return "single", [body]
        return None

    def bad_refs(self, line: str, in_queries: bool) -> list[str]:
        """Packages at structural positions on this line that are not allowed."""
        bad: list[str] = []
        for m in _QUERIES_LIST.finditer(line):
            bad += self._filter_list(m["list"])[1]
        if m2 := _BRACE_LIST.match(line):
            bad += self._filter_list(m2["list"])[1]
        bad += [p for p in _refs(line) if not self.ok(p)]
        if in_queries and (entry := self._queries_entry(line.strip())):
            bad += [p for p in entry[1] if not self.ok(p)]
        return bad

    # --- redaction -----------------------------------------------------------

    def _known_third_party(self) -> re.Pattern[str] | None:
        names = sorted(self.listed - self.system - set(self.allowed), key=len, reverse=True)
        if not names:
            return None
        return re.compile(r"(?<![\w.])(?:" + "|".join(map(re.escape, names)) + r")(?![A-Za-z0-9_])")

    def _mentions_known(self, line: str, known: re.Pattern[str] | None) -> str | None:
        """The first known third-party package mentioned on ``line``, if any."""
        if known is None:
            return None
        for m in known.finditer(line):
            token = re.match(r"[\w.]+", line[m.start() :])
            full = token.group(0) if token else m.group(0)
            # `com.foo` inside `com.foo.bar` only counts if com.foo.bar isn't allowed/system.
            if not any(
                full == p or full.startswith(p + ".") for p in (*self.allowed, *self.system)
            ):
                return m.group(0)
        return None

    def known_mentions(self, text: str) -> list[tuple[int, str]]:
        """(line, package) wherever a known, non-allowlisted third-party app is named.

        Unlike :meth:`scan`, this looks everywhere, not just at structural positions,
        but it only knows the apps in ``listed`` (e.g. from ``--third-party-list``).
        """
        known = self._known_third_party()
        found: list[tuple[int, str]] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            while (name := self._mentions_known(line, known)) is not None:
                found.append((lineno, name))
                line = line.replace(name, "")
        return found

    def _filter_line(
        self, line: str, in_queries: bool, known: re.Pattern[str] | None
    ) -> str | None:
        def filter_queries_list(m: re.Match[str]) -> str:
            body, dropped = self._filter_list(m["list"])
            self.removed += len(dropped)
            return m["pre"] + body + m["post"]

        line = _QUERIES_LIST.sub(filter_queries_list, line)

        def filter_worksource(m: re.Match[str]) -> str:
            items = [i.strip() for i in m["list"].split(",") if i.strip()]
            kept = [i for i in items if all(self.ok(p) for p in _worksource_packages(i))]
            self.removed += len(items) - len(kept)
            return m["pre"] + ", ".join(kept) + m["post"]

        line = _WORKSOURCE.sub(filter_worksource, line)
        if bm := _BRACE_LIST.match(line):
            body, dropped = self._filter_list(bm["list"])
            self.removed += len(dropped)
            if not body:
                return None
            line = bm["pre"] + body + bm["post"]
        if in_queries and (entry := self._queries_entry(line.strip())):
            kind, pkgs = entry
            if kind == "list":
                kept = [p for p in pkgs if self.ok(p)]
                self.removed += len(pkgs) - len(kept)
                if not kept:
                    return None
                stripped = line.strip()
                tail = ":" if stripped.endswith(":") else ""
                line = line[: _indent(line)] + "[" + ",".join(kept) + "]" + tail
            elif not self.ok(pkgs[0]):
                return None
        if any(not self.ok(p) for p in _refs(line)):
            return None
        if self._mentions_known(line, known) is not None:
            return None
        return line

    def _drop_recent_jobs(self, text: str, known: re.Pattern[str] | None) -> str:
        """Drop whole "Recently completed jobs" entries that involve a non-allowed app."""
        lines = text.splitlines(keepends=True)
        out: list[str] = []
        in_recent = False
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.strip() and not line[0].isspace():
                in_recent = line.startswith("Recently completed jobs:")
            if in_recent and _RECENT_HEADER.match(line.rstrip("\n")):
                end = i + 1
                while end < len(lines) and lines[end].strip() and _indent(lines[end]) > 2:
                    end += 1
                block = lines[i:end]
                if any(
                    any(not self.ok(p) for p in _refs(b)) or self._mentions_known(b, known)
                    for b in block
                ):
                    self.removed += len(block)
                else:
                    out += block
                i = end
                continue
            out.append(line)
            i += 1
        return "".join(out)

    def _redact_pm_list(self, text: str) -> str:
        lines = text.splitlines()
        out: list[str] = []
        present: set[str] = set()
        template: re.Match[str] | None = None
        for line in lines:
            m = _PM_LINE.match(line)
            if not m:
                out.append(line)
                continue
            name = m["name"]
            if name in self.system:
                out.append(line)
            elif name in self.allowed:
                template = template or m
                present.add(name)
                installer = _PM_INSTALLER.search(line)
                if installer and installer.group(0) != "null" and not self.ok(installer.group(0)):
                    line = _PM_INSTALLER.sub(self.allowed[name].installer, line)
                out.append(line)
            else:
                template = template or m
                self.removed += 1
        if template is not None:  # a third-party listing: make the allowlist complete
            while out and not out[-1].strip():
                out.pop()
            for i, entry in enumerate(self.allowlist):
                if entry.name not in present:
                    out.append(self._synthetic_line(template, entry, i))
        return "\n".join(out) + ("\n" if text.endswith("\n") else "")

    @staticmethod
    def _synthetic_line(template: re.Match[str], entry: AllowedPackage, i: int) -> str:
        path = f"/data/app/{entry.name}/base.apk=" if template["path"] else ""
        rest = _PM_INSTALLER.sub(entry.installer, template["rest"])
        rest = _PM_UID.sub(str(19000 + i), rest)
        return f"package:{path}{entry.name}{rest}"

    def _shared_user_ok(self, members: list[str]) -> bool:
        # A shared-user entry is named after its owner and lists the owner's
        # permissions, so it goes as a whole if any member isn't allowed.
        return bool(members) and all(self.ok(p) for p in members)

    def _drop_shared_users(self, text: str) -> str:
        lines = text.splitlines(keepends=True)
        drop = [(a, b) for a, b, _, members in _shared_user_entries(lines)
                if not self._shared_user_ok(members)]  # fmt: skip
        for a, b in reversed(drop):
            self.removed += b - a
            del lines[a:b]
        return "".join(lines)

    def _drop_uid_blocks(self, text: str) -> str:
        # A UID block without Package members holds only UID-level modes and an
        # app id, which identify nothing, so it stays.
        lines = text.splitlines(keepends=True)
        drop = [(a, b) for a, b, _, members in _uid_blocks(lines)
                if members and not all(self.ok(p) for p in members)]  # fmt: skip
        for a, b in reversed(drop):
            self.removed += b - a
            del lines[a:b]
        return "".join(lines)

    def _drop_activity_blocks(self, text: str) -> str:
        """Launcher query: a non-allowed app's block goes whole, and the rest are
        renumbered so the gaps don't show how many were dropped."""
        lines = text.splitlines(keepends=True)
        blocks = _owner_blocks(lines, _ACTIVITY_HEADER, _ACTIVITY_COMPONENT)
        for a, b, _, members in reversed(blocks):
            if not members or not all(self.ok(p) for p in members):
                self.removed += b - a
                del lines[a:b]
        n = 0
        for i, line in enumerate(lines):
            if _ACTIVITY_HEADER.match(line.rstrip("\n")):
                lines[i] = f"  Activity #{n}:" + line[len(line.rstrip("\n")) :]
                n += 1
        return "".join(lines)

    def redact(self, text: str) -> str:
        if is_pm_list(text):
            return self._redact_pm_list(text)
        if re.match(r"\d+ activities found:", text):
            text = self._drop_activity_blocks(text)
        if "SharedUser [" in text:
            text = self._drop_shared_users(text)
        if "\n  Uid " in text:
            text = self._drop_uid_blocks(text)
        known = self._known_third_party()
        if "Recently completed jobs:" in text:
            text = self._drop_recent_jobs(text, known)
        if "Location Settings:" in text:
            lines = text.splitlines(keepends=True)
            bad = {
                i
                for i in _location_settings_lines(lines)
                if not self.ok(_SETTINGS_PKG.match(lines[i].rstrip("\n"))["pkg"])  # type: ignore[index]
            }
            self.removed += len(bad)
            text = "".join(line for i, line in enumerate(lines) if i not in bad)
        out: list[str] = []
        in_queries = False
        skip_deeper_than: int | None = None
        for line in text.splitlines(keepends=True):
            content = line.rstrip("\n")
            if skip_deeper_than is not None:
                if content.strip() and _indent(content) > skip_deeper_than:
                    continue
                skip_deeper_than = None
            if content and not content[0].isspace():
                in_queries = content.rstrip() == "Queries:"
            uid_header = _UID_ONLY_HEADER.match(content)
            new = (
                None
                if uid_header and not self.uid_ok(uid_header["label"])
                else self._filter_line(content, in_queries, known)
            )
            if new is None:
                # A removed line takes its more-indented lines with it: they describe
                # it (a job's details, an alarm's tag and intent, a header's children).
                self.removed += 1
                skip_deeper_than = _indent(content)
                continue
            out.append(new + line[len(content) :])
        return "".join(out)

    # --- scanning --------------------------------------------------------------

    def scan(self, text: str) -> list[tuple[int, str]]:
        """(line number, package) for every non-allowed package at a structural position."""
        findings: list[tuple[int, str]] = []
        if is_pm_list(text):
            for lineno, line in enumerate(text.splitlines(), start=1):
                if m := _PM_LINE.match(line):
                    refs = [m["name"]] + [i.group(0) for i in _PM_INSTALLER.finditer(line)]
                    findings += [(lineno, p) for p in refs if p != "null" and not self.ok(p)]
            return findings
        in_queries = False
        lines = text.splitlines()
        for lineno, line in enumerate(lines, start=1):
            if line and not line[0].isspace():
                in_queries = line.rstrip() == "Queries:"
            findings += [(lineno, p) for p in self.bad_refs(line, in_queries)]
        for start, _, name, members in _shared_user_entries(lines):
            if not members:  # can't tell whose it is, so it can't be shown to be allowed
                findings.append((start + 1, name))
        for lineno, line in enumerate(lines, start=1):
            if (m := _UID_ONLY_HEADER.match(line)) and not self.uid_ok(m["label"]):
                findings.append((lineno, m["label"]))
        for i in _location_settings_lines(lines):
            pkg = _SETTINGS_PKG.match(lines[i])["pkg"]  # type: ignore[index]
            if not self.ok(pkg):
                findings.append((i + 1, pkg))
        return findings


def policy_for_tree(
    files: Iterable[tuple[str, str]], allowlist: tuple[AllowedPackage, ...] = DEFAULT_ALLOWLIST
) -> PackagePolicy:
    """Build a policy from (file name, text) pairs, harvesting system lists."""
    policy = PackagePolicy(allowlist=allowlist)
    for name, text in files:
        policy.harvest(name, text)
    return policy
