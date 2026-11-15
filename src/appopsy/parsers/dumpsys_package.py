"""Parser for the ``Packages:`` section of `dumpsys package`.

Works on per-app output (``dumpsys package <pkg>``) and on section dumps that
list every package. Only ``Packages:`` is read: ``Hidden system packages:``
holds the factory versions of updated system apps, and ``Queries:`` has its own
``User 0:`` lines that are not user state.

Runtime permission *grant state* is modelled on its own. AppOps *modes* are a
separate source and a separate model: a permission can be granted while its op
is ``foreground`` or ``ignore``, and the rules look at exactly that gap, so
nothing here records or infers a mode.

Apps that run under a shared UID (``sharedUser=SharedUserSetting{... name/uid}``)
have their runtime permissions printed under the *shared user* (a ``Shared
users:`` section), not in their own block. ``PackageInfo.shared_user`` records
this so a missing permission list is never mistaken for "no permissions".
``dumpsys package packages`` omits ``Shared users:``; per-app dumps include it.

Times (``timeStamp``, ``lastUpdateTime``, ``firstInstallTime``) are device-local
wall-clock times without an offset; convert them with the device clock.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

from pydantic import BaseModel

from appopsy.parsers.base import ParseWarning

SOURCE = "dumpsys package"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

_PACKAGE_HEADER = re.compile(r"^Package \[(?P<name>[A-Za-z][\w.]*)\] \([0-9a-f]+\):$")
_USER_HEADER = re.compile(r"^User (?P<id>\d+):(?P<rest>.*)$")
# Permission names can carry an owner prefix: `com.example.app#com.example.perm.ACCESS`.
_GRANT = re.compile(
    r"^(?P<name>[\w.$#-]+): granted=(?P<granted>true|false)(?:, flags=\[(?P<flags>[^\]]*)\])?\s*$"
)
_NAME = re.compile(r"^(?P<name>[\w.$#-]+)(?::.*)?$")
_SHARED_USER_HEADER = re.compile(r"^SharedUser \[(?P<name>[^\]]+)\] \([0-9a-f]+\):$")
_PACKAGE_SETTING = re.compile(r"^PackageSetting\{[0-9a-f]+ (?P<name>[A-Za-z][\w.]*)/\d+\}$")
_SHARED_USER = re.compile(
    r"^sharedUser=SharedUserSetting\{[0-9a-f]+ (?P<name>[^/}]+)/(?P<uid>\d+)\}$"
)
_TOKEN = re.compile(r"(?P<k>\w+)=(?P<v>\S*)")


class RuntimePermission(BaseModel):
    """Grant state of one runtime permission: what Settings > Permissions shows.

    Deliberately has no AppOps mode; see the module docstring.
    """

    name: str
    granted: bool
    flags: list[str]

    @property
    def user_set(self) -> bool:
        return "USER_SET" in self.flags

    @property
    def user_fixed(self) -> bool:
        """The user denied it and chose "Don't ask again"."""
        return "USER_FIXED" in self.flags


class InstallPermission(BaseModel):
    name: str
    granted: bool


class UserState(BaseModel):
    user_id: int
    installed: bool | None = None
    hidden: bool | None = None
    suspended: bool | None = None
    stopped: bool | None = None
    not_launched: bool | None = None
    enabled: int | None = None
    install_reason: int | None = None
    first_install_time: datetime | None = None
    data_dir: str | None = None
    runtime_permissions: list[RuntimePermission] = []
    disabled_components: list[str] = []
    enabled_components: list[str] = []


class PackageInfo(BaseModel):
    name: str
    app_id: int | None = None
    version_code: int | None = None
    version_name: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    flags: list[str] = []
    private_flags: list[str] = []
    installer: str | None = None
    update_owner: str | None = None
    shared_user: str | None = None  # runtime permissions live on the shared user, see module doc
    timestamp: datetime | None = None
    last_update_time: datetime | None = None
    requested_permissions: list[str] = []
    declared_permissions: list[str] = []
    install_permissions: list[InstallPermission] = []
    users: list[UserState] = []

    @property
    def is_system(self) -> bool:
        return "SYSTEM" in self.flags

    def runtime_permissions(self, user_id: int = 0) -> list[RuntimePermission]:
        for user in self.users:
            if user.user_id == user_id:
                return user.runtime_permissions
        return []


class SharedUser(BaseModel):
    """One shared UID: its member packages and the permissions they hold together."""

    name: str
    app_id: int | None = None
    packages: list[str] = []
    install_permissions: list[InstallPermission] = []
    users: list[UserState] = []

    def runtime_permissions(self, user_id: int = 0) -> list[RuntimePermission]:
        for user in self.users:
            if user.user_id == user_id:
                return user.runtime_permissions
        return []


def runtime_permissions_for(
    pkg: PackageInfo, shared_users: dict[str, SharedUser], user_id: int = 0
) -> list[RuntimePermission] | None:
    """A package's runtime permission grants, following its shared UID if it has one.

    Returns None when the package is shared-UID but that shared user wasn't
    collected: unknown, which is not the same as "no permissions".
    """
    if pkg.shared_user is None:
        return pkg.runtime_permissions(user_id)
    shared = shared_users.get(pkg.shared_user)
    return shared.runtime_permissions(user_id) if shared else None


# --- Indentation tree -------------------------------------------------------


@dataclass
class _Node:
    text: str
    lineno: int
    indent: int
    children: list[_Node] = field(default_factory=list)


def _tree(lines: list[tuple[int, str]]) -> list[_Node]:
    roots: list[_Node] = []
    stack: list[_Node] = []
    for lineno, line in lines:
        if not line.strip():
            continue
        node = _Node(line.strip(), lineno, len(line) - len(line.lstrip()))
        while stack and stack[-1].indent >= node.indent:
            stack.pop()
        (stack[-1].children if stack else roots).append(node)
        stack.append(node)
    return roots


def _section(text: str, header: str) -> list[tuple[int, str]] | None:
    """Lines of a top-level section (e.g. ``Packages:``), or None if there isn't one."""
    out: list[tuple[int, str]] = []
    found = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.strip() and not line[0].isspace():  # a top-level header
            if found:
                break
            found = line.rstrip() == header
        elif found:
            out.append((lineno, line))
    return out if found else None


# --- Interpretation ---------------------------------------------------------


class _Parser:
    def __init__(self) -> None:
        self.warnings: list[ParseWarning] = []

    def warn(self, node: _Node, message: str) -> None:
        self.warnings.append(
            ParseWarning(source=SOURCE, line=node.lineno, text=node.text, message=message)
        )

    def int_(self, node: _Node, value: str) -> int | None:
        try:
            return int(value)
        except ValueError:
            self.warn(node, f"not a number: {value!r}")
            return None

    def time(self, node: _Node, value: str) -> datetime | None:
        try:
            return datetime.strptime(value.strip(), TIME_FORMAT)
        except ValueError:
            self.warn(node, f"unrecognised time: {value!r}")
            return None

    def grants(self, node: _Node) -> list[tuple[str, bool, list[str]]]:
        out: list[tuple[str, bool, list[str]]] = []
        for child in node.children:
            m = _GRANT.match(child.text)
            if not m:
                self.warn(child, "not a permission grant line")
                continue
            flags = [f.strip() for f in (m["flags"] or "").split("|") if f.strip()]
            out.append((m["name"], m["granted"] == "true", flags))
        return out

    @staticmethod
    def names(node: _Node) -> list[str]:
        return [m["name"] for c in node.children if (m := _NAME.match(c.text))]

    def package(self, node: _Node, name: str) -> PackageInfo:
        pkg = PackageInfo(name=name)
        for child in node.children:
            text = child.text
            if text == "requested permissions:":
                pkg.requested_permissions = self.names(child)
            elif text == "declared permissions:":
                pkg.declared_permissions = self.names(child)
            elif text == "install permissions:":
                pkg.install_permissions = [
                    InstallPermission(name=n, granted=g) for n, g, _ in self.grants(child)
                ]
            elif m := _USER_HEADER.match(text):
                pkg.users.append(self.user(child, int(m["id"]), m["rest"]))
            else:
                self.scalar(child, pkg)
        return pkg

    def scalar(self, node: _Node, pkg: PackageInfo) -> None:
        key, _, value = node.text.partition("=")
        if key in ("timeStamp", "lastUpdateTime"):
            setattr(
                pkg,
                "timestamp" if key == "timeStamp" else "last_update_time",
                self.time(node, value),
            )
            return
        if key in ("flags", "privateFlags"):
            items = value.strip().removeprefix("[").removesuffix("]").split()
            setattr(pkg, "flags" if key == "flags" else "private_flags", items)
            return
        if m := _SHARED_USER.match(node.text):
            pkg.shared_user = m["name"]
            return
        if key == "versionName":
            pkg.version_name = value
            return
        for m in _TOKEN.finditer(node.text):
            k, v = m["k"], m["v"]
            if k == "appId":
                pkg.app_id = self.int_(node, v)
            elif k == "versionCode":
                pkg.version_code = self.int_(node, v)
            elif k == "minSdk":
                pkg.min_sdk = self.int_(node, v)
            elif k == "targetSdk":
                pkg.target_sdk = self.int_(node, v)
            elif k == "installerPackageName":
                pkg.installer = None if v == "null" else v
            elif k == "updateOwnerPackageName":
                pkg.update_owner = None if v == "null" else v

    def user(self, node: _Node, user_id: int, rest: str) -> UserState:
        user = UserState(user_id=user_id)
        bools = {"installed": "installed", "hidden": "hidden", "suspended": "suspended",
                 "stopped": "stopped", "notLaunched": "not_launched"}  # fmt: skip
        for m in _TOKEN.finditer(rest):
            if m["k"] in bools and m["v"] in ("true", "false"):
                setattr(user, bools[m["k"]], m["v"] == "true")
            elif m["k"] == "enabled":
                user.enabled = self.int_(node, m["v"])
        for child in node.children:
            key, _, value = child.text.partition("=")
            if child.text == "runtime permissions:":
                user.runtime_permissions = [
                    RuntimePermission(name=n, granted=g, flags=f) for n, g, f in self.grants(child)
                ]
            elif child.text == "disabledComponents:":
                user.disabled_components = [c.text for c in child.children]
            elif child.text == "enabledComponents:":
                user.enabled_components = [c.text for c in child.children]
            elif key == "installReason":
                user.install_reason = self.int_(child, value)
            elif key == "firstInstallTime":
                user.first_install_time = self.time(child, value)
            elif key == "dataDir":
                user.data_dir = value
        return user


def parse_shared_users(text: str) -> tuple[list[SharedUser], list[ParseWarning]]:
    """Parse the ``Shared users:`` section (`dumpsys package shared-users`)."""
    parser = _Parser()
    section = _section(text, "Shared users:")
    if section is None:
        return [], [ParseWarning(source=SOURCE, message="no Shared users: section")]
    users: list[SharedUser] = []
    for node in _tree(section):
        m = _SHARED_USER_HEADER.match(node.text)
        if not m:
            parser.warn(node, "expected 'SharedUser [name] (hash):'")
            continue
        shared = SharedUser(name=m["name"])
        for child in node.children:
            key, _, value = child.text.partition("=")
            if key == "appId":
                shared.app_id = parser.int_(child, value)
            elif child.text == "Packages":
                shared.packages = [
                    pm["name"] for c in child.children if (pm := _PACKAGE_SETTING.match(c.text))
                ]
            elif child.text == "install permissions:":
                shared.install_permissions = [
                    InstallPermission(name=n, granted=g) for n, g, _ in parser.grants(child)
                ]
            elif um := _USER_HEADER.match(child.text):
                shared.users.append(parser.user(child, int(um["id"]), um["rest"]))
        users.append(shared)
    return users, parser.warnings


def parse_dumpsys_package(text: str) -> tuple[list[PackageInfo], list[ParseWarning]]:
    parser = _Parser()
    section = _section(text, "Packages:")
    if section is None:
        return [], [ParseWarning(source=SOURCE, message="no Packages: section")]
    packages: list[PackageInfo] = []
    for node in _tree(section):
        m = _PACKAGE_HEADER.match(node.text)
        if not m:
            parser.warn(node, "expected 'Package [name] (hash):'")
            continue
        packages.append(parser.package(node, m["name"]))
    return packages, parser.warnings
