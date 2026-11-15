"""Allowlisted, read-only adb runner.

Every adb invocation in appopsy goes through :class:`Adb`. Before anything is
executed, the full argument vector is checked against an explicit allowlist of
read-only commands. Anything else raises :class:`CommandRefusedError` and no
process is started.

The allowlist is exact, token by token, rather than "deny known-bad". Even
``dumpsys`` is not safe in general: ``dumpsys battery set level 5`` and
``dumpsys deviceidle force-idle`` both change device state. So each permitted
command is spelled out, and every argument that varies (package names, op
names, property keys) must match a strict pattern that cannot carry shell
metacharacters. ``adb shell`` joins its arguments and runs them through the
device's ``sh``, so this is what stops ``getprop; reboot`` style injection.

The allowlist contains only commands appopsy actually runs (its collectors and
the ``devices`` command); a test fails if any rule goes unused. A new collector
adds its command here in the same change, after a human has reviewed it (see
CLAUDE.md).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from appopsy.parsers.base import ParseWarning
from appopsy.parsers.devices import Device, parse_devices

# --- Token patterns ---------------------------------------------------------

# System property key, e.g. ro.build.version.security_patch.
PROP_KEY = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\-]*")
# adb serial: USB serials, ip:port, and mDNS names (adb-XXXX._adb-tls-connect._tcp).
# Must not start with '-' so it can't be read as an option.
SERIAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:\-]*")
# Defence in depth: every token sent to `adb shell` must also match this.
# No spaces, quotes, ; | & $ ` < > ( ) * ? ~ ! \ or newlines.
_SAFE_SHELL_TOKEN = re.compile(r"[A-Za-z0-9._:+%/=\-]+")


Matcher = str | re.Pattern[str]


@dataclass(frozen=True)
class Rule:
    """One allowed command shape. Strings match literally; patterns must fullmatch."""

    pattern: tuple[Matcher, ...]

    def matches(self, args: Sequence[str]) -> bool:
        if len(args) != len(self.pattern):
            return False
        for matcher, arg in zip(self.pattern, args, strict=True):
            if isinstance(matcher, str):
                if arg != matcher:
                    return False
            elif not matcher.fullmatch(arg):
                return False
        return True


# --- The allowlist ----------------------------------------------------------

# Commands run on the device via `adb [-s SERIAL] shell ...`. Each is used by a
# collector (or by `appopsy devices`, for the getprop keys it shows).
LAUNCHER_QUERY = ("pm", "query-activities", "--brief", "-a", "android.intent.action.MAIN",
                  "-c", "android.intent.category.LAUNCHER")  # fmt: skip

ALLOWED_SHELL: tuple[Rule, ...] = (
    Rule(("getprop",)),  # collectors/getprop
    Rule(("getprop", PROP_KEY)),  # `devices` table; device model for the case folder name
    Rule(("date", "+%s")),  # collectors/date
    Rule(("date", "+%Y-%m-%dT%H:%M:%S%z")),  # collectors/date
    Rule(("pm", "list", "packages", "-3", "-i")),  # collectors/packages
    Rule(("pm", "list", "packages", "-s")),  # collectors/packages
    Rule(("dumpsys", "package", "packages")),  # collectors/dumpsys_package
    Rule(("dumpsys", "package", "shared-users")),  # collectors/dumpsys_package; no "s" alias
    Rule(("dumpsys", "appops")),  # collectors/appops
    Rule(("dumpsys", "jobscheduler")),  # collectors/jobscheduler; no arguments
    Rule(("dumpsys", "alarm")),  # collectors/alarm; no arguments
    Rule(("dumpsys", "location")),  # collectors/location; no arguments
    # collectors/launcher: apps with a launcher icon. Only the `pm` form, never
    # `cmd package query-activities` (same query, but `cmd package` changes state).
    Rule(LAUNCHER_QUERY),
)

# Commands run against the local adb server (no `shell`).
ALLOWED_HOST: tuple[Rule, ...] = (
    Rule(("devices", "-l")),  # device listing and selection
)


# --- Errors -----------------------------------------------------------------


class AdbError(Exception):
    """Base class for adb wrapper errors."""


class CommandRefusedError(AdbError):
    """The command is not on the read-only allowlist and was not executed."""

    def __init__(self, args: Sequence[str]) -> None:
        self.args_refused = tuple(args)
        super().__init__(
            f"Refused: `adb {' '.join(args)}` is not on appopsy's read-only allowlist. "
            "appopsy never runs commands that could change your device."
        )


class AdbNotFoundError(AdbError):
    """The adb executable could not be found."""


class AdbTimeoutError(AdbError):
    """adb did not finish within the timeout."""


class AdbCommandError(AdbError):
    """adb exited with a non-zero status."""

    def __init__(self, args: Sequence[str], returncode: int, stderr: str) -> None:
        self.returncode = returncode
        self.stderr = stderr
        detail = stderr.strip() or "(no error output)"
        super().__init__(f"`adb {' '.join(args)}` failed with exit code {returncode}: {detail}")


class DeviceSelectionError(AdbError):
    """No single usable device could be chosen."""


# --- Allowlist check --------------------------------------------------------


def check_allowed(args: Sequence[str]) -> None:
    """Raise :class:`CommandRefusedError` unless ``args`` is on the allowlist."""
    if not args or not all(isinstance(a, str) for a in args):
        raise CommandRefusedError([str(a) for a in args])
    if args[0] == "shell":
        command = args[1:]
        if all(_SAFE_SHELL_TOKEN.fullmatch(a) for a in command) and any(
            rule.matches(command) for rule in ALLOWED_SHELL
        ):
            return
    elif any(rule.matches(args) for rule in ALLOWED_HOST):
        return
    raise CommandRefusedError(args)


# --- Runner -----------------------------------------------------------------


@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[list[str], float], RunResult]


def _subprocess_runner(argv: list[str], timeout: float) -> RunResult:
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise AdbNotFoundError(f"Could not run adb at {argv[0]!r}") from exc
    except subprocess.TimeoutExpired as exc:
        raise AdbTimeoutError(f"`{' '.join(argv)}` timed out after {timeout:g}s") from exc
    return RunResult(
        proc.returncode,
        proc.stdout.decode("utf-8", errors="replace"),
        proc.stderr.decode("utf-8", errors="replace"),
    )


def find_adb(adb_path: str | None = None) -> str:
    """Return the adb executable to use, or raise :class:`AdbNotFoundError`."""
    if adb_path:
        return adb_path
    found = shutil.which("adb")
    if found is None:
        raise AdbNotFoundError(
            "adb was not found on your PATH. Install Android platform-tools "
            "(https://developer.android.com/tools/releases/platform-tools) "
            "or pass --adb /path/to/adb."
        )
    return found


class Adb:
    """Read-only adb client. The only way appopsy talks to a device."""

    def __init__(
        self,
        serial: str | None = None,
        *,
        adb_path: str | None = None,
        timeout: float = 60.0,
        runner: Runner | None = None,
    ) -> None:
        if serial is not None and not SERIAL.fullmatch(serial):
            raise DeviceSelectionError(f"Invalid device serial: {serial!r}")
        self.serial = serial
        self.timeout = timeout
        self._adb_path = adb_path
        self._custom_runner = runner

    def with_serial(self, serial: str) -> Adb:
        return Adb(
            serial, adb_path=self._adb_path, timeout=self.timeout, runner=self._custom_runner
        )

    def _argv(self, args: Sequence[str]) -> list[str]:
        # With an injected runner (tests) adb needn't be installed.
        adb = self._adb_path or ("adb" if self._custom_runner else find_adb())
        argv = [adb]
        if self.serial is not None and args[0] == "shell":
            argv += ["-s", self.serial]
        return [*argv, *args]

    def _run(self, args: Sequence[str], timeout: float | None) -> str:
        check_allowed(args)
        runner = self._custom_runner or _subprocess_runner
        result = runner(self._argv(args), timeout or self.timeout)
        if result.returncode != 0:
            raise AdbCommandError(args, result.returncode, result.stderr)
        return result.stdout

    def host(self, *args: str, timeout: float | None = None) -> str:
        """Run an allowlisted host command, e.g. ``host("devices", "-l")``."""
        return self._run(args, timeout)

    def shell(self, *args: str, timeout: float | None = None) -> str:
        """Run an allowlisted command on the device, e.g. ``shell("getprop", "ro.serialno")``."""
        if self.serial is None:
            raise DeviceSelectionError("No device selected; call select_device() first.")
        return self._run(("shell", *args), timeout)

    def list_devices(self) -> tuple[list[Device], list[ParseWarning]]:
        """Return attached devices and any lines that couldn't be parsed."""
        return parse_devices(self.host("devices", "-l"))


# --- Device selection -------------------------------------------------------

STATE_HINTS: dict[str, str] = {
    "unauthorized": "Unlock the phone and accept the 'Allow USB debugging?' prompt.",
    "offline": "The phone isn't responding to adb. Unplug it and plug it back in.",
    "recovery": "The phone is in recovery mode. Reboot it into Android.",
    "sideload": "The phone is in sideload mode. Reboot it into Android.",
    "bootloader": "The phone is in the bootloader. Reboot it into Android.",
    "host": "This is a host connection, not a phone.",
}


def state_hint(state: str) -> str | None:
    if state.startswith("no permissions"):
        return "Your user can't access this USB device (on Linux, check your udev rules)."
    return STATE_HINTS.get(state)


def select_device(devices: Sequence[Device], serial: str | None = None) -> Device:
    """Choose the device to audit, or raise :class:`DeviceSelectionError` with advice."""
    if serial is not None:
        for device in devices:
            if device.serial == serial:
                if not device.ready:
                    hint = state_hint(device.state) or ""
                    raise DeviceSelectionError(
                        f"Device {serial} is {device.state!r}, not ready. {hint}".strip()
                    )
                return device
        known = ", ".join(d.serial for d in devices) or "none"
        raise DeviceSelectionError(f"No device with serial {serial}. Connected: {known}.")

    ready = [d for d in devices if d.ready]
    if len(ready) == 1:
        return ready[0]
    if len(ready) > 1:
        serials = ", ".join(d.serial for d in ready)
        raise DeviceSelectionError(
            f"Several devices are connected ({serials}). Choose one with --serial."
        )
    if not devices:
        raise DeviceSelectionError(
            "No devices found. Connect your phone by USB and enable USB debugging "
            "(Settings > System > Developer options)."
        )
    hints = {h for d in devices if (h := state_hint(d.state))}
    raise DeviceSelectionError("A device is connected but not ready. " + " ".join(sorted(hints)))
