"""Command-line interface: appopsy devices | audit | watch | report."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from appopsy import __version__, redact
from appopsy.adb import Adb, AdbError, select_device, state_hint
from appopsy.case import Case
from appopsy.collectors import Collector
from appopsy.collectors import alarm as alarm_collector
from appopsy.collectors import appops as appops_collector
from appopsy.collectors import date as date_collector
from appopsy.collectors import dumpsys_package as dumpsys_package_collector
from appopsy.collectors import getprop as getprop_collector
from appopsy.collectors import jobscheduler as jobscheduler_collector
from appopsy.collectors import launcher as launcher_collector
from appopsy.collectors import location as location_collector
from appopsy.collectors import packages as packages_collector
from appopsy.parsers.devices import Device
from appopsy.redact_packages import (
    DEFAULT_ALLOWLIST,
    DEFAULT_THIRD_PARTY_LIST,
    PackagePolicy,
    check_outside_repo,
    load_allowlist,
    load_third_party_list,
    mask_apps,
)
from appopsy.report import run as report_run
from appopsy.report.redaction import RedactionError

app = typer.Typer(
    help="An autopsy of what your Android apps have been doing. Read-only.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)

AdbPathOption = Annotated[
    str | None,
    typer.Option("--adb", envvar="APPOPSY_ADB", help="Path to the adb executable."),
]

RedactOption = Annotated[
    bool,
    typer.Option(
        "--redact",
        help="Also write a shareable copy: unlisted apps get aliases, device identifiers refused.",
    ),
]
PackOption = Annotated[str, typer.Option("--pack", help="Rule pack: privacy, security or all.")]


def _check_pack(pack: str) -> None:
    if pack not in report_run.PACKS:
        err_console.print(f"[red]Error:[/red] unknown pack {pack!r}: use privacy, security or all")
        raise typer.Exit(2)


# getprop keys shown by `appopsy devices` for each ready device.
DEVICE_PROPS = {
    "manufacturer": "ro.product.manufacturer",
    "android": "ro.build.version.release",
    "sdk": "ro.build.version.sdk",
    "security_patch": "ro.build.version.security_patch",
}


# Run in order; date last so its timestamp is close to the other snapshots.
COLLECTORS: list[tuple[str, Collector]] = [
    ("getprop", getprop_collector.collect),
    ("packages", packages_collector.collect),
    ("dumpsys package", dumpsys_package_collector.collect),
    ("appops", appops_collector.collect),
    ("jobscheduler", jobscheduler_collector.collect),
    ("alarm", alarm_collector.collect),
    ("location", location_collector.collect),
    ("launcher", launcher_collector.collect),
    ("date", date_collector.collect),
]


def make_adb(adb_path: str | None) -> Adb:
    """Build the adb client. Tests replace this to inject a fake runner."""
    return Adb(adb_path=adb_path)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"appopsy {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """An autopsy of what your Android apps have been doing. Read-only."""


def _device_props(adb: Adb, device: Device) -> dict[str, str | None]:
    """Read a few build properties. Failures leave a field empty rather than aborting."""
    props: dict[str, str | None] = dict.fromkeys(DEVICE_PROPS)
    if not device.ready:
        return props
    client = adb.with_serial(device.serial)
    for field, key in DEVICE_PROPS.items():
        try:
            props[field] = client.shell("getprop", key, timeout=10).strip() or None
        except AdbError:
            props[field] = None
    return props


@app.command()
def devices(
    adb_path: AdbPathOption = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON instead of a table.")] = False,
) -> None:
    """List connected devices and whether appopsy can audit them."""
    adb = make_adb(adb_path)
    try:
        found, warnings = adb.list_devices()
    except AdbError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc

    rows = [(d, _device_props(adb, d)) for d in found]

    if as_json:
        payload = [
            {**d.model_dump(), "ready": d.ready, "hint": state_hint(d.state), **props}
            for d, props in rows
        ]
        console.print_json(json.dumps(payload))
        return

    for warning in warnings:
        err_console.print(f"[yellow]Warning:[/yellow] couldn't parse line: {warning.text!r}")

    if not rows:
        console.print(
            "No devices found. Connect your phone by USB and enable USB debugging "
            "(Settings > System > Developer options)."
        )
        return

    table = Table(title="Connected devices")
    table.add_column("Serial")
    table.add_column("State")
    table.add_column("Device")
    table.add_column("Android")
    table.add_column("Security patch")
    for d, props in rows:
        state = "[green]ready[/green]" if d.ready else f"[yellow]{d.state}[/yellow]"
        name = " ".join(filter(None, [props["manufacturer"], d.display_model])) or "?"
        android = f"{props['android']} (SDK {props['sdk']})" if props["android"] else "?"
        table.add_row(d.serial, state, name, android, props["security_patch"] or "?")
    console.print(table)

    for d, _ in rows:
        if (hint := state_hint(d.state)) and not d.ready:
            console.print(f"[yellow]{d.serial}:[/yellow] {hint}")


@app.command()
def audit(
    serial: Annotated[
        str | None, typer.Option("--serial", "-s", help="Device serial, if several are connected.")
    ] = None,
    cases_dir: Annotated[
        Path, typer.Option("--cases-dir", help="Where to create the case folder.")
    ] = Path("cases"),
    adb_path: AdbPathOption = None,
    pack: PackOption = "privacy",
    redact: RedactOption = False,
) -> None:
    """Collect a snapshot from the phone, run the rules and write the report.

    Everything goes into a new case folder: raw/ (the phone's output as
    collected), parsed/findings.json and report/report.md. `appopsy report
    <case folder>` re-renders it later without the phone.
    """
    _check_pack(pack)
    adb = make_adb(adb_path)
    try:
        found, _ = adb.list_devices()
        device = select_device(found, serial)
    except AdbError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc

    client = adb.with_serial(device.serial)
    try:
        model = client.shell("getprop", "ro.product.model", timeout=10).strip() or None
    except AdbError:
        model = device.display_model

    case = Case.create(cases_dir, serial=device.serial, model=model)
    console.print(f"Collecting from [bold]{model or device.serial}[/bold] into {case.root}")
    for label, collect in COLLECTORS:
        with console.status(f"{label}..."):
            collect(client, case)

    failed = [c for c in case.manifest.commands if not c.ok]
    ok = len(case.manifest.commands) - len(failed)
    console.print(f"[green]{ok} command(s) saved[/green] to {case.raw}")
    for c in failed:
        console.print(f"[yellow]Failed:[/yellow] {' '.join(c.command)}: {c.error}")
    with console.status("parsing and running rules..."):
        analysis = report_run.analyse(case.raw, pack)
        try:
            outputs = report_run.write_case_outputs(case.root, analysis, redact=redact)
        except RedactionError as exc:
            err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1) from exc
    _announce(outputs, analysis.warnings)


@app.command()
def report(
    folder: Annotated[
        Path,
        typer.Argument(
            exists=True, file_okay=False, help="A case folder from `audit` (or a capture folder)."
        ),
    ],
    out: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "-o",
            help="Write here (.html for HTML, else Markdown). Default for a case folder: "
            "report/report.md and report.html (report-redacted.* with --redact); for a "
            "capture folder: Markdown to stdout.",
        ),
    ] = None,
    pack: PackOption = "privacy",
    redact: Annotated[
        bool,
        typer.Option(
            "--redact",
            help="Write the shareable copy instead: unlisted apps get aliases, "
            "device identifiers refused.",
        ),
    ] = False,
) -> None:
    """Parse a case folder, run the rules and write the report (Markdown and HTML). Offline."""
    _check_pack(pack)
    raw_dir, default_out = report_run.resolve(folder)
    analysis = report_run.analyse(raw_dir, pack)
    try:
        rendered = analysis.render(redact=redact)
        written: list[Path] = []
        if out is None and default_out is not None:  # a case folder: both formats
            md_name = report_run.REDACTED_NAME if redact else report_run.MARKDOWN_NAME
            html_name = report_run.REDACTED_HTML_NAME if redact else report_run.HTML_NAME
            for name, text in ((md_name, rendered.markdown), (html_name, rendered.html)):
                report_run.write_private(default_out.with_name(name), text)
                written.append(default_out.with_name(name))
        else:
            html = out is not None and out.suffix.lower() in (".html", ".htm")
            text = rendered.html if html else rendered.markdown
            if out is None:
                sys.stdout.write(text)
            else:
                report_run.write_private(out, text)
                written.append(out)
    except RedactionError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc
    _announce(written, analysis.warnings)


def _announce(paths: list[Path], warnings: int) -> None:
    """What `audit` and `report` wrote, in the same words: each file, then the one to
    open (the full HTML report if there is one, else the redacted copy). Parse
    warnings go to stderr, so a report printed to stdout stays clean."""
    for path in paths:
        console.print(f"Written: {path}", soft_wrap=True)
    pages = [p for p in paths if p.suffix == ".html"]
    page = next((p for p in pages if p.name == report_run.HTML_NAME), pages[0] if pages else None)
    if page is not None:
        console.print(f"[bold]Open your report: {page.resolve()}[/bold]", soft_wrap=True)
    if warnings:
        err_console.print(
            f"[yellow]{warnings} line(s) couldn't be parsed[/yellow]; see the report."
        )


# Developer commands: hidden from `appopsy --help` (they're for building test
# fixtures, see the README's Development section) but they work as before.
@app.command("mask", hidden=True)
def mask(
    paths: Annotated[
        list[Path] | None,
        typer.Argument(exists=True, dir_okay=False, help="Files to print masked (default: stdin)."),
    ] = None,
    third_party_list: Annotated[
        Path,
        typer.Option("--third-party-list", help="Your app list, kept outside the repo."),
    ] = DEFAULT_THIRD_PARTY_LIST,
) -> None:
    """Print raw capture text with your apps masked, for exploring a capture.

    Every token containing one of your non-allowlisted apps becomes <app>, including
    class names and actions attached to it. Use this for all exploration of raw
    captures; never an ad-hoc mask.
    """
    try:
        check_outside_repo(third_party_list)
        names = load_third_party_list(third_party_list)
    except (OSError, ValueError) as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    allowed = [a.name for a in DEFAULT_ALLOWLIST]
    sources = (
        [p.read_text(encoding="utf-8", errors="replace") for p in paths]
        if paths
        else [sys.stdin.read()]
    )
    for text in sources:
        sys.stdout.write(mask_apps(text, names, allowed))


@app.command("redact-fixture", hidden=True)
def redact_fixture(
    sources: Annotated[
        list[Path],
        typer.Argument(exists=True, metavar="PATH...", help="Raw dump files or directories."),
    ],
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Directory to write redacted copies to.")
    ] = None,
    extra: Annotated[
        list[str] | None,
        typer.Option("--extra", help="Another literal to redact everywhere (repeatable)."),
    ] = None,
    mapping: Annotated[
        Path | None,
        typer.Option(help="Write original->placeholder map here (contains personal data!)."),
    ] = None,
    packages: Annotated[
        Path | None,
        typer.Option(
            "--packages",
            exists=True,
            help="Third-party package allowlist ('package [installer]' per line). "
            "Default: the built-in public set.",
        ),
    ] = None,
    third_party_list: Annotated[
        Path | None,
        typer.Option(
            "--third-party-list",
            exists=True,
            dir_okay=False,
            help="Your own installed apps (pm list packages -3 output), kept outside the "
            "repo. --check fails if any is named anywhere; redaction removes them. Local only.",
        ),
    ] = None,
    apps_only: Annotated[
        bool,
        typer.Option(
            "--apps-only",
            help="With --check --third-party-list: report only mentions of your apps "
            "(for docs, tests and code, which contain synthetic identifiers on purpose).",
        ),
    ] = False,
    force: Annotated[bool, typer.Option(help="Write into a non-empty --out directory.")] = False,
    check: Annotated[
        bool, typer.Option("--check", help="Only scan for identifiers; exit 1 if any.")
    ] = False,
) -> None:
    """Strip personal identifiers from raw dumps so they can become test fixtures.

    Replacement is consistent across all files: the same serial, MAC or email
    becomes the same placeholder everywhere.
    """
    try:
        allowlist = load_allowlist(packages) if packages else DEFAULT_ALLOWLIST
        my_apps: set[str] = set()
        if third_party_list is not None:
            check_outside_repo(third_party_list)
            my_apps = load_third_party_list(third_party_list)
    except ValueError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if apps_only and not (check and my_apps):
        err_console.print("[red]Error:[/red] --apps-only needs --check and --third-party-list.")
        raise typer.Exit(2)

    if check:
        findings = redact.scan_tree(sources, allowlist, my_apps or None)
        if apps_only:
            findings = [(p, f) for p, f in findings if f.category == "my_app"]
        for path, f in findings:
            console.print(f"[red]{f.category}[/red] {path}:{f.line} {redact.mask(f.value)}")
        if findings:
            err_console.print(f"[red]{len(findings)} identifier(s) found.[/red]")
            raise typer.Exit(1)
        if apps_only:
            console.print(f"[green]None of your {len(my_apps)} listed apps is named.[/green]")
        else:
            checked = f" or any of your {len(my_apps)} listed apps" if my_apps else ""
            console.print(f"[green]No identifiers{checked} found.[/green]")
        return

    if out is None:
        err_console.print("[red]Error:[/red] --out is required (or use --check).")
        raise typer.Exit(2)
    out_resolved = out.resolve()
    for src in sources:
        s = src.resolve()
        if out_resolved == s or (s.is_dir() and out_resolved.is_relative_to(s)):
            err_console.print("[red]Error:[/red] --out must not be inside a source directory.")
            raise typer.Exit(2)
    if out.exists() and any(out.iterdir()) and not force:
        err_console.print(f"[red]Error:[/red] {out} is not empty. Use --force to write into it.")
        raise typer.Exit(2)
    if mapping is not None and mapping.resolve().is_relative_to(out_resolved):
        err_console.print("[red]Error:[/red] --mapping must not be inside --out.")
        raise typer.Exit(2)

    redactor = redact.Redactor(
        extra=extra or [], packages=PackagePolicy(allowlist=allowlist, listed=set(my_apps))
    )
    result = redact.redact_tree(sources, out, redactor)
    if not redactor.packages.system_known and redactor.packages.removed:
        err_console.print(
            "[yellow]Warning:[/yellow] no pm-list-packages-system.txt in the input, so every "
            "package not on the allowlist was treated as third-party."
        )

    for path, reason in result.skipped:
        err_console.print(f"[yellow]Skipped[/yellow] {path}: {reason}")

    if result.remaining:
        for path, f in result.remaining:
            err_console.print(
                f"[red]Still present:[/red] {f.category} {path}:{f.line} {redact.mask(f.value)}"
            )
        err_console.print("[red]Nothing was written.[/red]")
        raise typer.Exit(1)

    table = Table(title=f"Redacted {len(result.written)} file(s) into {out}")
    table.add_column("Category")
    table.add_column("Replacements", justify="right")
    table.add_column("Distinct values", justify="right")
    for category in sorted(redactor.counts):
        distinct = len(redactor.mapping.get(category, {}))
        table.add_row(category, str(redactor.counts[category]), str(distinct))
    console.print(table)

    if mapping is not None:
        mapping.write_text(json.dumps(redactor.mapping, indent=2, sort_keys=True))
        console.print(f"[yellow]Mapping written to {mapping}. It contains personal data.[/yellow]")

    console.print(
        "Not redacted: system package names, build fingerprints. "
        "[bold]Review the diff by hand before committing.[/bold]"
    )
