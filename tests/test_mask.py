"""`appopsy mask`: exploring raw captures without printing your apps (synthetic names)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from appopsy import cli
from appopsy.redact_packages import mask_apps

NAMES = {"com.example.bank", "net.example.vpn", "com.whatsapp"}
ALLOWED = ["com.whatsapp"]


def test_whole_token_is_masked_including_attached_class_names() -> None:
    text = (
        "      tag=*walarm*:net.example.vpn/.service.TunnelKeepAliveListener \n"
        "    RTC #1: Alarm{a1 type 1 origWhen 0 whenElapsed 1 com.example.bank}\n"
        "      tag=*alarm*:WakingExecutorService.ACTION_ALARM.com.example.bank.Sync\n"
        "  JOB #u0a1/2: ab #W#@androidx.work.systemjobscheduler@com.example.bank/androidx.work.X\n"
        "    com.whatsapp, u0: -1m\n"
        "    com.example.bankruptcy is someone else\n"
    )
    out = mask_apps(text, NAMES, ALLOWED)
    for leak in [
        "example.vpn",
        "TunnelKeepAlive",
        "example.bank/",
        "ACTION_ALARM.com.example",
        ".Sync",
    ]:
        assert leak not in out, leak
    assert "tag=*walarm*:<app> \n" in out
    assert "whenElapsed 1 <app>}\n" in out
    assert "    com.whatsapp, u0: -1m\n" in out  # allowlisted: not masked
    assert "com.example.bankruptcy" in out  # a different name


def test_cli_masks_files_and_refuses_a_list_in_a_repo(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    my_apps = home / "my-apps.txt"
    my_apps.write_text("package:com.example.bank  installer=com.android.vending\n")
    dump = tmp_path / "raw.txt"
    dump.write_text("Source: uid=u0a500 user=0 pkg=com.example.bank\n")
    runner = CliRunner()
    result = runner.invoke(cli.app, ["mask", "--third-party-list", str(my_apps), str(dump)])
    assert result.exit_code == 0, result.output
    assert result.output == "Source: uid=u0a500 user=0 pkg=<app>\n"
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "my-apps.txt").write_text("com.example.bank\n")
    refused = runner.invoke(
        cli.app, ["mask", "--third-party-list", str(repo / "my-apps.txt"), str(dump)]
    )
    assert refused.exit_code == 2
