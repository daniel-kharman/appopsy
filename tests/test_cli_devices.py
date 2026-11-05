from __future__ import annotations

import json

import pytest
from rich.console import Console
from typer.testing import CliRunner

from appopsy import cli
from appopsy.adb import Adb, AdbNotFoundError
from tests.conftest import FakeRunner

runner = CliRunner()

DEVICES = """\
List of devices attached
FAKESERIAL01           device usb:1-1 product:grizzly model:Pixel_11_Pro device:grizzly transport_id:1
FAKESERIAL02           unauthorized usb:1-2 transport_id:2
"""

PROPS = {
    "ro.product.manufacturer": "Google",
    "ro.build.version.release": "17",
    "ro.build.version.sdk": "37",
    "ro.build.version.security_patch": "2026-10-05",
}


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeRunner:
    responses: dict[tuple[str, ...], str] = {("devices", "-l"): DEVICES}
    for key, value in PROPS.items():
        responses[("-s", "FAKESERIAL01", "shell", "getprop", key)] = value + "\n"
    fake_runner = FakeRunner(responses)  # type: ignore[arg-type]
    monkeypatch.setattr(cli, "make_adb", lambda adb_path: Adb(runner=fake_runner))
    monkeypatch.setattr(cli, "console", Console(width=200))
    return fake_runner


def test_devices_table(fake: FakeRunner) -> None:
    result = runner.invoke(cli.app, ["devices"])
    assert result.exit_code == 0, result.output
    assert "FAKESERIAL01" in result.output
    assert "ready" in result.output
    assert "Google Pixel 11 Pro" in result.output
    assert "2026-10-05" in result.output
    assert "unauthorized" in result.output
    assert "Allow USB debugging" in result.output
    # Only the ready device is queried for properties.
    assert not any("FAKESERIAL02" in call for call in fake.calls)


def test_devices_json(fake: FakeRunner) -> None:
    result = runner.invoke(cli.app, ["devices", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data[0]["serial"] == "FAKESERIAL01"
    assert data[0]["ready"] is True
    assert data[0]["android"] == "17"
    assert data[1]["ready"] is False
    assert "Allow USB debugging" in data[1]["hint"]


def test_devices_none_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_runner = FakeRunner({("devices", "-l"): "List of devices attached\n\n"})
    monkeypatch.setattr(cli, "make_adb", lambda adb_path: Adb(runner=fake_runner))
    result = runner.invoke(cli.app, ["devices"])
    assert result.exit_code == 0
    assert "No devices found" in result.output


def test_devices_adb_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(argv: list[str], timeout: float) -> None:
        raise AdbNotFoundError("adb was not found on your PATH.")

    monkeypatch.setattr(cli, "make_adb", lambda adb_path: Adb(runner=boom))  # type: ignore[arg-type]
    result = runner.invoke(cli.app, ["devices"])
    assert result.exit_code == 1
    assert "adb was not found" in result.output


def test_version() -> None:
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert "appopsy" in result.output
