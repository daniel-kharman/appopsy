"""Proves the adb wrapper is read-only: state-changing commands never reach a process."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from appopsy import adb, cli
from appopsy.adb import Adb, AdbCommandError, CommandRefusedError, RunResult, check_allowed
from tests.conftest import FakeRunner

# Device commands that change state, plus injection attempts that smuggle one
# inside an allowed command. None of these may ever be executed.
REFUSED_SHELL: list[list[str]] = [
    # Package manager writes
    ["pm", "uninstall", "com.example.app"],
    ["pm", "uninstall", "-k", "--user", "0", "com.example.app"],
    ["pm", "disable", "com.example.app"],
    ["pm", "disable-user", "--user", "0", "com.example.app"],
    ["pm", "enable", "com.example.app"],
    ["pm", "clear", "com.example.app"],
    ["pm", "grant", "com.example.app", "android.permission.CAMERA"],
    ["pm", "revoke", "com.example.app", "android.permission.CAMERA"],
    ["pm", "install", "/sdcard/x.apk"],
    ["pm", "hide", "com.example.app"],
    ["pm", "suspend", "com.example.app"],
    ["pm", "list", "packages", "-3", "uninstall"],
    # AppOps writes
    ["appops", "set", "com.example.app", "CAMERA", "deny"],
    ["appops", "reset"],
    ["appops", "get", "com.example.app"],  # even reads only via the exact `cmd appops get` form
    ["cmd", "appops", "set", "com.example.app", "CAMERA", "deny"],
    ["cmd", "appops", "reset", "com.example.app"],
    ["cmd", "appops", "get", "com.example.app", "CAMERA", "extra"],
    ["cmd", "appops", "get"],
    ["cmd", "appops", "get", "com.example.app;reboot"],
    ["dumpsys", "appops", "--package", "com.example.app"],
    ["dumpsys", "appops", "--op", "CAMERA", "--package", "com.example.app"],
    ["dumpsys", "appops", "--package", "com.example.app", "--op", "CAMERA", "--history"],
    ["dumpsys", "appops", "--package", "com.example.app;reboot", "--op", "CAMERA"],
    ["dumpsys", "appops", "--history", "--package", "com.example.app"],
    ["dumpsys", "appops", "--history", "extra"],
    ["dumpsys", "appops", "--clear"],
    # Settings / properties
    ["settings", "put", "global", "adb_enabled", "0"],
    ["settings", "delete", "secure", "location_mode"],
    ["setprop", "persist.sys.timezone", "UTC"],
    # Activity manager, input, package service
    ["am", "start", "-a", "android.intent.action.VIEW"],
    ["am", "force-stop", "com.example.app"],
    ["am", "broadcast", "-a", "x"],
    ["input", "tap", "100", "100"],
    ["input", "keyevent", "26"],
    ["cmd", "package", "uninstall", "com.example.app"],
    ["cmd", "package", "list", "packages"],
    ["cmd", "jobscheduler", "run", "-f", "com.example.app", "1"],
    ["cmd", "deviceidle", "force-idle"],
    # dumpsys is NOT blanket-safe: some services take write arguments
    ["dumpsys", "battery", "set", "level", "5"],
    ["dumpsys", "battery", "reset"],
    ["dumpsys", "deviceidle", "force-idle"],
    ["dumpsys", "alarm", "--set"],
    ["dumpsys", "package", "com.example.app", "extra"],
    ["dumpsys", "package", "f"],
    ["dumpsys", "package"],
    ["dumpsys", "package", "packages", "com.example.app"],
    ["dumpsys", "package", "packages", "--checkin"],
    ["dumpsys", "package", "packages;reboot"],
    ["dumpsys", "package", "p"],
    # shared-users: only the long form is allowed
    ["dumpsys", "package", "s"],
    ["dumpsys", "package", "s", "noperm"],
    ["dumpsys", "package", "shared-users", "noperm"],
    ["dumpsys", "package", "shared-user"],
    ["dumpsys", "package", "sharedusers"],
    ["dumpsys", "package", "--shared-users"],
    ["dumpsys", "package", "shared-users", "com.example.app"],
    ["dumpsys", "package", "shared-users;reboot"],
    ["dumpsys"],
    # Power, radios, files
    ["reboot"],
    ["reboot", "recovery"],
    ["svc", "wifi", "disable"],
    ["rm", "-rf", "/sdcard"],
    ["sh", "-c", "getprop"],
    ["su", "-c", "id"],
    ["kill", "1"],
    ["date", "-s", "20200101"],
    ["date", "010100002020"],
    # Shell injection inside otherwise-allowed commands
    ["getprop", "ro.serialno;reboot"],
    ["getprop", "ro.serialno", ";", "reboot"],
    ["getprop", "ro.serialno&&reboot"],
    ["getprop", "ro.serialno|sh"],
    ["getprop", "$(reboot)"],
    ["getprop", "`reboot`"],
    ["getprop", "ro.serialno\nreboot"],
    ["getprop", "ro.x >/sdcard/x"],
    ["getprop", "ro x"],
    ["dumpsys", "package", "com.example.app;reboot"],
    ["dumpsys", "package", "com.example.app$(reboot)"],
    ["cmd", "appops", "get", "com.example.app", "CAMERA;reboot"],
    ["pm", "list", "packages", "-3;reboot"],
    ["pm", "list", "packages", "-3", "-3"],
    # Empty
    [],
]

REFUSED_HOST: list[list[str]] = [
    ["install", "app.apk"],
    ["uninstall", "com.example.app"],
    ["reboot"],
    ["root"],
    ["unroot"],
    ["remount"],
    ["disable-verity"],
    ["push", "x", "/sdcard/x"],
    ["pull", "/sdcard/x"],
    ["tcpip", "5555"],
    ["usb"],
    ["kill-server"],
    ["connect", "10.0.0.1"],
    ["disconnect"],
    ["sideload", "x.zip"],
    ["backup", "-all"],
    ["restore", "x.ab"],
    ["forward", "tcp:1", "tcp:1"],
    ["reverse", "tcp:1", "tcp:1"],
    ["exec-out", "getprop"],
    ["devices", "-l", "extra"],
    ["-s", "SERIAL", "reboot"],
    ["-s", "SERIAL", "shell", "getprop"],
    ["shell"],
]

ALLOWED_SHELL: list[list[str]] = [
    ["getprop"],
    ["getprop", "ro.build.version.security_patch"],
    ["date", "+%s"],
    ["date", "+%Y-%m-%dT%H:%M:%S%z"],
    ["pm", "list", "packages", "-3", "-i"],
    ["pm", "list", "packages", "-s"],
    ["dumpsys", "package", "packages"],
    ["dumpsys", "package", "shared-users"],
    ["dumpsys", "appops"],
    ["dumpsys", "jobscheduler"],
    ["dumpsys", "alarm"],
    ["dumpsys", "location"],
    ["pm", "query-activities", "--brief", "-a", "android.intent.action.MAIN",
     "-c", "android.intent.category.LAUNCHER"],
]  # fmt: skip

# Launcher query: only the exact `pm` form. `cmd package query-activities` is the
# same query, but `cmd package` is refused as a whole because its other subcommands
# change state; other pm query forms and other intents are refused too.
LAUNCHER = ["-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER"]
REFUSED_LAUNCHER: list[list[str]] = [
    ["cmd", "package", "query-activities", "--brief", *LAUNCHER],
    ["cmd", "package", "query-activities", *LAUNCHER],
    ["cmd", "package", "resolve-activity", "--brief", *LAUNCHER],
    ["pm", "query-activities", *LAUNCHER],
    ["pm", "query-activities", "--brief"],
    ["pm", "query-activities", "--brief", "-a", "android.intent.action.MAIN"],
    ["pm", "query-activities", "--brief", *LAUNCHER, "--user", "0"],
    ["pm", "query-activities", "--brief", *LAUNCHER, "com.facebook.katana"],
    ["pm", "query-activities", "--brief", "-c", "android.intent.category.LAUNCHER",
     "-a", "android.intent.action.MAIN"],
    ["pm", "query-activities", "--brief", "-a", "android.intent.action.VIEW",
     "-c", "android.intent.category.LAUNCHER"],
    ["pm", "query-activities", "--brief", "-a", "android.intent.action.MAIN",
     "-c", "android.intent.category.HOME"],
    ["pm", "query-services", "--brief", *LAUNCHER],
    ["pm", "query-receivers", "--brief", *LAUNCHER],
    ["pm", "resolve-activity", "--brief", *LAUNCHER],
    ["pm", "query-activities", "--brief", *LAUNCHER[:3], "android.intent.category.LAUNCHER;reboot"],
]  # fmt: skip


@pytest.mark.parametrize("command", REFUSED_LAUNCHER, ids=" ".join)
def test_launcher_query_only_exact_pm_form(command: list[str]) -> None:
    runner = FakeRunner()
    with pytest.raises(CommandRefusedError):
        Adb("SERIAL123", runner=runner).shell(*command)
    assert runner.calls == []


# location: only the bare dumpsys form. `cmd location` can switch location on or
# off, add test providers and inject locations, so every form is refused.
REFUSED_LOCATION: list[list[str]] = [
    ["dumpsys", "location", "com.facebook.katana"],
    ["dumpsys", "location", "--gnssmetrics"],
    ["dumpsys", "location", "--location"],
    ["dumpsys", "location", "-a"],
    ["dumpsys", "location", "-h"],
    ["dumpsys", "location", "--proto"],
    ["dumpsys", "location;reboot"],
    ["cmd", "location"],
    ["cmd", "location", "is-location-enabled"],
    ["cmd", "location", "set-location-enabled", "false"],
    ["cmd", "location", "providers", "add-test-provider", "gps"],
    ["cmd", "location", "providers", "set-test-provider-location", "gps", "--location", "0,0"],
    ["cmd", "location", "providers", "remove-test-provider", "gps"],
    ["cmd", "location", "set-adas-gnss-location-enabled", "false"],
    ["cmd", "location", "send-extra-command", "gps", "delete_aiding_data"],
]


@pytest.mark.parametrize("command", REFUSED_LOCATION, ids=" ".join)
def test_location_only_bare_dumpsys(command: list[str]) -> None:
    runner = FakeRunner()
    with pytest.raises(CommandRefusedError):
        Adb("SERIAL123", runner=runner).shell(*command)
    assert runner.calls == []


# jobscheduler / alarm: only the bare dumpsys form. Arguments (package filters,
# --proto, -h, ...) and the `cmd` service forms, some of which run or force jobs
# and alarms, are refused.
REFUSED_JOBS_ALARMS: list[list[str]] = [
    ["dumpsys", "jobscheduler", "com.facebook.katana"],
    ["dumpsys", "jobscheduler", "-u", "0"],
    ["dumpsys", "jobscheduler", "--proto"],
    ["dumpsys", "jobscheduler", "-h"],
    ["dumpsys", "jobscheduler", "-a"],
    ["dumpsys", "jobscheduler", "jobscheduler"],
    ["dumpsys", "jobscheduler;reboot"],
    ["dumpsys", "alarm", "com.facebook.katana"],
    ["dumpsys", "alarm", "--proto"],
    ["dumpsys", "alarm", "-h"],
    ["dumpsys", "alarm", "-a"],
    ["dumpsys", "alarm;reboot"],
    ["cmd", "jobscheduler"],
    ["cmd", "jobscheduler", "run", "-f", "com.facebook.katana", "1"],
    ["cmd", "jobscheduler", "timeout", "com.facebook.katana", "1"],
    ["cmd", "jobscheduler", "cancel", "com.facebook.katana"],
    ["cmd", "jobscheduler", "monitor-battery", "on"],
    ["cmd", "jobscheduler", "get-job-state", "com.facebook.katana", "1"],
    ["cmd", "alarm"],
    ["cmd", "alarm", "set-time", "0"],
    ["cmd", "alarm", "set-timezone", "UTC"],
    ["cmd", "alarm", "get-next-alarm"],
]


@pytest.mark.parametrize("command", REFUSED_JOBS_ALARMS, ids=" ".join)
def test_jobscheduler_and_alarm_only_bare_dumpsys(command: list[str]) -> None:
    runner = FakeRunner()
    with pytest.raises(CommandRefusedError):
        Adb("SERIAL123", runner=runner).shell(*command)
    assert runner.calls == []


# Read-only commands that used to be allowlisted but no collector runs. The
# allowlist holds only what appopsy actually uses, so these are refused now.
PRUNED_SHELL: list[list[str]] = [
    ["pm", "list", "packages"],
    ["pm", "list", "packages", "-3"],
    ["pm", "list", "packages", "-i", "-3"],  # same flags, different order
    ["pm", "list", "packages", "-3", "-i", "-U"],
    ["pm", "list", "packages", "-f"],
    ["pm", "list", "packages", "-s", "-i"],
    ["dumpsys", "package", "com.facebook.katana"],
    ["dumpsys", "appops", "--package", "com.facebook.katana", "--op", "FINE_LOCATION"],
    ["dumpsys", "appops", "--history"],
    ["cmd", "appops", "get", "com.facebook.katana"],
    ["cmd", "appops", "get", "com.facebook.katana", "FINE_LOCATION"],
    ["cmd", "appops", "get", "com.example.app", "RUN_ANY_IN_BACKGROUND"],
]
PRUNED_HOST: list[list[str]] = [["devices"]]


@pytest.mark.parametrize("command", PRUNED_SHELL, ids=" ".join)
def test_unused_read_only_shell_commands_are_refused(command: list[str]) -> None:
    runner = FakeRunner()
    with pytest.raises(CommandRefusedError):
        Adb("SERIAL123", runner=runner).shell(*command)
    assert runner.calls == []


@pytest.mark.parametrize("command", PRUNED_HOST, ids=" ".join)
def test_unused_host_commands_are_refused(command: list[str]) -> None:
    with pytest.raises(CommandRefusedError):
        Adb(runner=FakeRunner()).host(*command)


def test_every_allowlist_rule_is_used_by_appopsy(tmp_path: Path) -> None:
    """The allowlist only contains commands a collector (or `devices`) actually runs.

    Runs `devices` and a full `audit` against a fake device, records every adb
    call, and fails if any rule matched none of them. Adding a rule without the
    collector that uses it fails here.
    """
    calls: list[list[str]] = []

    def record(argv: list[str], timeout: float) -> RunResult:
        args = argv[1:]
        if args[:1] == ["-s"]:
            args = args[2:]
        calls.append(args)
        if args == ["devices", "-l"]:
            return RunResult(0, "List of devices attached\nSERIAL123 device model:X\n", "")
        return RunResult(0, "", "")

    original = cli.make_adb
    cli.make_adb = lambda adb_path: Adb(runner=record)
    try:
        for argv in (["devices"], ["audit", "--cases-dir", str(tmp_path)]):
            result = CliRunner().invoke(cli.app, argv)
            assert result.exit_code == 0, result.output
    finally:
        cli.make_adb = original
    shell = [c[1:] for c in calls if c[:1] == ["shell"]]
    host = [c for c in calls if c[:1] != ["shell"]]
    unused = [r.pattern for r in adb.ALLOWED_SHELL if not any(r.matches(c) for c in shell)]
    unused += [r.pattern for r in adb.ALLOWED_HOST if not any(r.matches(c) for c in host)]
    assert unused == [], f"allowlist rules no collector uses: {unused}"


@pytest.mark.parametrize("command", REFUSED_SHELL, ids=lambda c: " ".join(c) or "<empty>")
def test_state_changing_shell_commands_are_refused_and_never_run(command: list[str]) -> None:
    runner = FakeRunner()
    adb = Adb("SERIAL123", runner=runner)
    with pytest.raises(CommandRefusedError):
        adb.shell(*command)
    assert runner.calls == [], "a refused command must never reach the process runner"


@pytest.mark.parametrize("command", REFUSED_HOST, ids=" ".join)
def test_state_changing_host_commands_are_refused_and_never_run(command: list[str]) -> None:
    runner = FakeRunner()
    adb = Adb("SERIAL123", runner=runner)
    with pytest.raises(CommandRefusedError):
        adb.host(*command)
    assert runner.calls == []


@pytest.mark.parametrize("command", ALLOWED_SHELL, ids=" ".join)
def test_read_only_shell_commands_are_allowed(command: list[str]) -> None:
    check_allowed(["shell", *command])


def test_allowed_shell_command_runs_with_serial() -> None:
    runner = FakeRunner(
        {("-s", "SERIAL123", "shell", "getprop", "ro.build.version.release"): "17\n"}
    )
    adb = Adb("SERIAL123", runner=runner)
    assert adb.shell("getprop", "ro.build.version.release") == "17\n"
    assert runner.calls == [
        ["adb", "-s", "SERIAL123", "shell", "getprop", "ro.build.version.release"]
    ]


def test_host_devices_is_allowed() -> None:
    runner = FakeRunner({("devices", "-l"): "List of devices attached\n"})
    assert Adb(runner=runner).host("devices", "-l") == "List of devices attached\n"


def test_refusal_message_explains_read_only() -> None:
    with pytest.raises(CommandRefusedError, match="read-only allowlist"):
        check_allowed(["shell", "pm", "uninstall", "com.example.app"])


@pytest.mark.parametrize("serial", ["-d", "--help", "a b", "x;reboot", ""])
def test_invalid_serial_is_rejected(serial: str) -> None:
    with pytest.raises(Exception, match="Invalid device serial"):
        Adb(serial, runner=FakeRunner())


def test_shell_requires_a_selected_device() -> None:
    with pytest.raises(Exception, match="No device selected"):
        Adb(runner=FakeRunner()).shell("getprop")


def test_non_zero_exit_raises_with_stderr() -> None:
    runner = FakeRunner(
        {("-s", "SERIAL123", "shell", "dumpsys", "appops"): RunResult(1, "", "boom")}
    )
    with pytest.raises(AdbCommandError, match="boom"):
        Adb("SERIAL123", runner=runner).shell("dumpsys", "appops")
