from __future__ import annotations

import json
import stat
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from appopsy import cli
from appopsy.adb import Adb, CommandRefusedError, RunResult
from appopsy.case import Case, raw_filename, slugify
from appopsy.collectors import (
    alarm,
    appops,
    date,
    dumpsys_package,
    getprop,
    jobscheduler,
    launcher,
    location,
    packages,
    run_and_save,
)
from tests.conftest import FakeRunner

FIXTURES = Path(__file__).parent / "fixtures" / "17-google" / "capture-1"
SERIAL = "FAKESERIAL0001"


def ticking_clock(start: datetime) -> Iterator[datetime]:
    t = start
    while True:
        yield t
        t += timedelta(milliseconds=100)


@pytest.fixture
def clock() -> object:
    ticks = ticking_clock(datetime(2026, 10, 30, 7, 48, 44, tzinfo=UTC))
    return lambda: next(ticks)


def fixture_responses() -> dict[tuple[str, ...], str | RunResult]:
    shell = ("-s", SERIAL, "shell")
    return {
        (*shell, "getprop"): (FIXTURES / "getprop.txt").read_text(),
        (*shell, "date", "+%s"): (FIXTURES / "date-epoch.txt").read_text(),
        (*shell, "date", "+%Y-%m-%dT%H:%M:%S%z"): (FIXTURES / "date-local.txt").read_text(),
        (*shell, "pm", "list", "packages", "-3", "-i"): (
            FIXTURES / "pm-list-packages-3p.txt"
        ).read_text(),
        (*shell, "pm", "list", "packages", "-s"): (
            FIXTURES / "pm-list-packages-system.txt"
        ).read_text(),
        (*shell, "dumpsys", "package", "packages"): (
            FIXTURES / "dumpsys-package-packages.txt"
        ).read_text(),
        (*shell, "dumpsys", "package", "shared-users"): (
            FIXTURES / "dumpsys-package-shared-users.txt"
        ).read_text(),
    }


def test_slug_and_filenames() -> None:
    assert slugify("Pixel 11 Pro") == "pixel-11-pro"
    assert slugify(None) == "device"
    assert raw_filename(["dumpsys", "package", "com.example.app"]) == (
        "dumpsys_package_com.example.app.txt"
    )
    assert raw_filename(["date", "+%s"]) == "date_-s.txt"


def test_case_create_layout_and_permissions(tmp_path: Path, clock: object) -> None:
    case = Case.create(tmp_path, serial=SERIAL, model="Pixel 11 Pro", clock=clock)  # type: ignore[arg-type]
    assert case.root.name == "20261030T074844Z-pixel-11-pro"
    assert case.raw.is_dir() and case.parsed.is_dir()
    assert stat.S_IMODE(case.root.stat().st_mode) == 0o700
    assert stat.S_IMODE((case.root / "manifest.json").stat().st_mode) == 0o600


def test_case_names_do_not_collide(tmp_path: Path) -> None:
    fixed = datetime(2026, 10, 30, tzinfo=UTC)
    a = Case.create(tmp_path, serial=SERIAL, model="X", clock=lambda: fixed)
    b = Case.create(tmp_path, serial=SERIAL, model="X", clock=lambda: fixed)
    assert a.root != b.root
    assert b.root.name.endswith("-2")


def test_collectors_save_raw_verbatim_and_record_manifest(tmp_path: Path, clock: object) -> None:
    runner = FakeRunner(fixture_responses())
    adb = Adb(SERIAL, runner=runner)
    case = Case.create(tmp_path, serial=SERIAL, model="Pixel 11 Pro", clock=clock)  # type: ignore[arg-type]
    getprop.collect(adb, case)
    date.collect(adb, case)

    assert (case.raw / "getprop.txt").read_text() == (FIXTURES / "getprop.txt").read_text()
    assert (case.raw / "date-epoch.txt").read_text() == (FIXTURES / "date-epoch.txt").read_text()
    assert stat.S_IMODE((case.raw / "getprop.txt").stat().st_mode) == 0o600

    reloaded = Case.load(case.root)
    cmds = reloaded.manifest.commands
    assert [c.file for c in cmds] == ["getprop.txt", "date-epoch.txt", "date-local.txt"]
    assert all(c.ok and c.finished > c.started for c in cmds)
    assert cmds[0].bytes == len((FIXTURES / "getprop.txt").read_bytes())


def test_failed_command_is_recorded_and_run_continues(tmp_path: Path, clock: object) -> None:
    responses = fixture_responses()
    responses[("-s", SERIAL, "shell", "date", "+%s")] = RunResult(1, "", "date: oops")
    adb = Adb(SERIAL, runner=FakeRunner(responses))
    case = Case.create(tmp_path, serial=SERIAL, model=None, clock=clock)  # type: ignore[arg-type]
    date.collect(adb, case)
    first, second = case.manifest.commands
    assert not first.ok and first.file is None and "oops" in (first.error or "")
    assert second.ok and second.file == "date-local.txt"


def test_refused_command_is_a_bug_and_propagates(tmp_path: Path) -> None:
    adb = Adb(SERIAL, runner=FakeRunner())
    case = Case.create(tmp_path, serial=SERIAL, model=None)
    with pytest.raises(CommandRefusedError):
        run_and_save(adb, case, ["pm", "uninstall", "com.example.app"])


def test_duplicate_raw_names_get_suffixes(tmp_path: Path, clock: object) -> None:
    adb = Adb(SERIAL, runner=FakeRunner(fixture_responses()))
    case = Case.create(tmp_path, serial=SERIAL, model=None, clock=clock)  # type: ignore[arg-type]
    getprop.collect(adb, case)
    getprop.collect(adb, case)
    assert [c.file for c in case.manifest.commands] == ["getprop.txt", "getprop-2.txt"]


def test_audit_cli_creates_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    responses = fixture_responses()
    responses[("devices", "-l")] = (
        f"List of devices attached\n{SERIAL} device product:grizzly model:Pixel_11_Pro\n"
    )
    responses[("-s", SERIAL, "shell", "getprop", "ro.product.model")] = "Pixel 11 Pro\n"
    fake = FakeRunner(responses)
    monkeypatch.setattr(cli, "make_adb", lambda adb_path: Adb(runner=fake))
    monkeypatch.setattr(cli, "console", Console(width=300))

    result = CliRunner().invoke(cli.app, ["audit", "--cases-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    (case_dir,) = tmp_path.iterdir()
    assert case_dir.name.endswith("-pixel-11-pro")
    assert sorted(p.name for p in (case_dir / "raw").iterdir()) == [
        "date-epoch.txt", "date-local.txt", "dumpsys-alarm.txt", "dumpsys-appops.txt",
        "dumpsys-jobscheduler.txt", "dumpsys-location.txt", "dumpsys-package-packages.txt",
        "dumpsys-package-shared-users.txt", "getprop.txt",
        "pm-list-packages-3p.txt", "pm-list-packages-system.txt", "pm-query-launcher.txt",
    ]  # fmt: skip
    assert "12 command(s) saved" in result.output
    # End to end: parsed findings and the report, written privately.
    report = case_dir / "report" / "report.md"
    findings = json.loads((case_dir / "parsed" / "findings.json").read_text())
    assert report.read_text().startswith("# appopsy report: Pixel 11 Pro")
    assert findings["packs"] == ["privacy"] and isinstance(findings["findings"], list)
    assert all("text" not in w for w in findings["parse_warnings"])  # no raw lines
    for path in (report, case_dir / "parsed" / "findings.json"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(report.parent.stat().st_mode) == 0o700
    assert f"Written: {report}" in result.output


def test_audit_refuses_an_unknown_pack_before_touching_the_phone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeRunner()
    monkeypatch.setattr(cli, "make_adb", lambda adb_path: Adb(runner=fake))
    result = CliRunner().invoke(cli.app, ["audit", "--cases-dir", str(tmp_path), "--pack", "x"])
    assert result.exit_code == 2
    assert fake.calls == [] and list(tmp_path.iterdir()) == []


def test_audit_with_all_packs_renders_both_sections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    responses = fixture_responses()
    responses[("devices", "-l")] = f"List of devices attached\n{SERIAL} device model:X\n"
    monkeypatch.setattr(cli, "make_adb", lambda adb_path: Adb(runner=FakeRunner(responses)))
    result = CliRunner().invoke(cli.app, ["audit", "--cases-dir", str(tmp_path), "--pack", "all"])
    assert result.exit_code == 0, result.output
    (case_dir,) = tmp_path.iterdir()
    text = (case_dir / "report" / "report.md").read_text()
    assert "## Privacy findings" in text and "## Security findings" in text


def test_audit_cli_reports_selection_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeRunner({("devices", "-l"): "List of devices attached\nA device\nB device\n"})
    monkeypatch.setattr(cli, "make_adb", lambda adb_path: Adb(runner=fake))
    result = CliRunner().invoke(cli.app, ["audit", "--cases-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "--serial" in result.output
    assert list(tmp_path.iterdir()) == []


def test_packages_collector_saves_both_lists(tmp_path: Path, clock: object) -> None:
    adb = Adb(SERIAL, runner=FakeRunner(fixture_responses()))
    case = Case.create(tmp_path, serial=SERIAL, model=None, clock=clock)  # type: ignore[arg-type]
    packages.collect(adb, case)
    assert [c.command for c in case.manifest.commands] == [
        ["pm", "list", "packages", "-3", "-i"],
        ["pm", "list", "packages", "-s"],
    ]
    assert (case.raw / "pm-list-packages-3p.txt").read_text() == (
        FIXTURES / "pm-list-packages-3p.txt"
    ).read_text()


def test_dumpsys_package_collector(tmp_path: Path, clock: object) -> None:
    adb = Adb(SERIAL, runner=FakeRunner(fixture_responses()))
    case = Case.create(tmp_path, serial=SERIAL, model=None, clock=clock)  # type: ignore[arg-type]
    dumpsys_package.collect(adb, case)
    assert [(c.command, c.file) for c in case.manifest.commands] == [
        (["dumpsys", "package", "packages"], "dumpsys-package-packages.txt"),
        (["dumpsys", "package", "shared-users"], "dumpsys-package-shared-users.txt"),
    ]
    for c in case.manifest.commands:
        assert c.file is not None
        assert (case.raw / c.file).read_text() == (FIXTURES / c.file).read_text()


def test_appops_collector(tmp_path: Path, clock: object) -> None:
    dump = "AppOps Service state:\n  Uid u0a426:\n    state=top\n"
    adb = Adb(SERIAL, runner=FakeRunner({("-s", SERIAL, "shell", "dumpsys", "appops"): dump}))
    case = Case.create(tmp_path, serial=SERIAL, model=None, clock=clock)  # type: ignore[arg-type]
    appops.collect(adb, case)
    (record,) = case.manifest.commands
    assert (record.command, record.file) == (["dumpsys", "appops"], "dumpsys-appops.txt")
    assert (case.raw / "dumpsys-appops.txt").read_text() == dump


@pytest.mark.parametrize(
    ("module", "service"),
    [(jobscheduler, "jobscheduler"), (alarm, "alarm"), (location, "location")],
)
def test_jobscheduler_and_alarm_collectors(
    tmp_path: Path, clock: object, module: object, service: str
) -> None:
    dump = f"synthetic {service} dump\n"
    adb = Adb(SERIAL, runner=FakeRunner({("-s", SERIAL, "shell", "dumpsys", service): dump}))
    case = Case.create(tmp_path, serial=SERIAL, model=None, clock=clock)  # type: ignore[arg-type]
    module.collect(adb, case)  # type: ignore[attr-defined]
    (record,) = case.manifest.commands
    assert (record.command, record.file) == (["dumpsys", service], f"dumpsys-{service}.txt")
    assert (case.raw / f"dumpsys-{service}.txt").read_text() == dump


def test_launcher_collector(tmp_path: Path, clock: object) -> None:
    dump = "1 activities found:\n  Activity #0:\n    com.example.app/.Main\n"
    key = ("-s", SERIAL, "shell", *launcher.COMMAND)
    adb = Adb(SERIAL, runner=FakeRunner({key: dump}))
    case = Case.create(tmp_path, serial=SERIAL, model=None, clock=clock)  # type: ignore[arg-type]
    launcher.collect(adb, case)
    (record,) = case.manifest.commands
    assert (record.command, record.file) == (launcher.COMMAND, "pm-query-launcher.txt")
    assert (case.raw / "pm-query-launcher.txt").read_text() == dump
