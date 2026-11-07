"""Privacy rules against the capture fixtures. Thresholds are not tuned to make
any app fire: where an app is under a threshold, the test says it doesn't fire."""

from __future__ import annotations

from pathlib import Path

import pytest

from appopsy.rules.case import CaseData
from appopsy.rules.engine import SEVERITIES, Finding, load_rules, run_rules

CAPTURES = Path(__file__).parent / "fixtures" / "17-google"


@pytest.fixture(scope="module")
def findings() -> dict[str, list[Finding]]:
    specs = load_rules()
    out = {}
    for capture in ("capture-1", "capture-2", "capture-3", "capture-4", "capture-5"):
        case = CaseData(CAPTURES / capture)
        out[capture] = run_rules(case, specs)
        assert case.warnings == []
    return out


def pick(findings: list[Finding], rule: str, package: str) -> list[Finding]:
    return [f for f in findings if f.rule_id == rule and f.package == package]


def test_facebook_is_under_the_wakeup_threshold_so_it_does_not_fire(
    findings: dict[str, list[Finding]],
) -> None:
    # 24 Mqtt_Wakeup wakeups in ~26.5 h is ~0.9 per hour, below 10.
    assert pick(findings["capture-2"], "chatty-wakeups", "com.facebook.katana") == []
    assert pick(findings["capture-2"], "chatty-wakeups", "com.facebook.orca") == []


def test_system_apps_over_the_threshold_go_to_the_system_section(
    findings: dict[str, list[Finding]],
) -> None:
    (gms,) = pick(findings["capture-2"], "chatty-wakeups", "com.google.android.gms")
    assert (gms.section, gms.severity, gms.app_class) == ("system", "info", "system")
    assert gms.facts["wakeups"] == 1365 and gms.facts["per_hour"] > 10


def test_only_wakeup_alarms_count_towards_chatty_wakeups(tmp_path: Path) -> None:
    """3600 non-waking alarms in an hour don't fire; 11 wakeup alarms do."""
    (tmp_path / "pm-list-packages-3p.txt").write_text(
        "package:org.example.quiet  installer=com.android.vending\n"
        "package:org.example.chatty  installer=com.android.vending\n"
    )
    (tmp_path / "dumpsys-alarm.txt").write_text(
        "Current Alarm Manager state:\n"
        "    Runtime uptime (elapsed): +1h0m0s0ms\n"
        "  Alarm Stats:\n"
        "  u0a501:org.example.quiet +1s0ms running, 0 wakeups:\n"
        "    +1s0ms 0 wakes 3600 alarms, last -1s0ms:\n"
        "      *alarm*:org.example.quiet.TICK\n"
        "  u0a502:org.example.chatty +1s0ms running, 11 wakeups:\n"
        "    +1s0ms 11 wakes 11 alarms, last -1s0ms:\n"
        "      *walarm*:org.example.chatty.SYNC\n"
    )
    case = CaseData(tmp_path)
    specs = [s for s in load_rules() if s.id == "chatty-wakeups"]
    fired = run_rules(case, specs)
    assert case.warnings == []
    assert [(f.package, f.facts["per_hour"]) for f in fired] == [("org.example.chatty", 11.0)]


def test_over_privileged_ranks_installed_and_system_apps_separately(
    findings: dict[str, list[Finding]],
) -> None:
    for capture in ("capture-1", "capture-2", "capture-3"):
        fs = [f for f in findings[capture] if f.rule_id == "over-privileged-app"]
        assert {f.severity for f in fs} == {"info"}  # a ranking, no threshold
        (fb,) = [f for f in fs if f.section == "main"]
        assert fb.package == "com.facebook.katana"
        assert (fb.facts["rank"], fb.facts["of"]) == (1, 1)
        assert fb.facts["allowed"] == {
            "CAMERA": "foreground",
            "COARSE_LOCATION": "foreground",
            "FINE_LOCATION": "foreground",
            "READ_MEDIA_VISUAL_USER_SELECTED": "allow",
        }
        system = sorted((f.facts["rank"], f.package, len(f.facts["allowed"]))
                        for f in fs if f.section == "system")  # fmt: skip
        # com.google.android.as appears under two UIDs but is ranked once.
        assert system == [
            (1, "com.google.android.as", 9),
            (2, "com.google.android.apps.maps", 8),
            (3, "com.google.android.dialer", 4),
        ]


def test_over_privileged_ranks_every_installed_app(findings: dict[str, list[Finding]]) -> None:
    """capture-4 keeps appops for all five allowlisted apps: a real ranking, down to
    an app with nothing allowed. Counted by kind of access, not by Android op; ties go
    to more at any time, then more full (not partial), then name."""
    fs = [f for f in findings["capture-4"] if f.rule_id == "over-privileged-app"]
    main = sorted((f for f in fs if f.section == "main"), key=lambda f: f.facts["rank"])
    assert [(f.facts["rank"], f.package, f.facts["count"]) for f in main] == [
        (1, "com.whatsapp", 5),
        (2, "com.facebook.katana", 2),  # selected photos only: shown, not counted
        (3, "com.facebook.orca", 2),
        (4, "com.tencent.mm", 1),
        (5, "com.twitter.android", 0),
    ]
    assert {f.facts["of"] for f in main} == {5} and {f.facts["checked"] for f in main} == {9}
    assert {f.severity for f in main} == {"info"}
    x = main[-1]
    assert x.facts["allowed"] == {} and "isn't allowed any of the 9" in x.summary and x.evidence
    assert main[0].facts["categories"] == {
        "location": {"mode": "foreground", "scope": "full"},
        "camera": {"mode": "foreground", "scope": "full"},
        "microphone": {"mode": "foreground", "scope": "full"},
        "contacts": {"mode": "allow", "scope": "full"},
        "photos_videos": {"mode": "allow", "scope": "full"},
    }
    fb = main[1]
    assert fb.facts["categories"]["photos_videos"] == {"mode": "allow", "scope": "partial"}
    assert "It can see only the photos and videos you picked." in fb.summary
    assert "photos" not in fb.summary.split(".")[0]  # not listed as access it holds


def test_capture4_classifies_every_facebook_network_job(
    findings: dict[str, list[Finding]],
) -> None:
    (fb,) = pick(findings["capture-4"], "unconstrained-background-work", "com.facebook.katana")
    assert fb.facts["undetermined"] == 0 and len(fb.facts["jobs"]) == 14
    what = {j["what"] for j in fb.facts["jobs"]}
    assert {"StoryTrayPredictionPrefetchWorker", "FeedBackgroundPrefetchWorker"} <= what
    assert "NewsFeedCacheInvalidationWorker" not in what  # requires charging and idle
    (orca,) = pick(findings["capture-4"], "unconstrained-background-work", "com.facebook.orca")
    assert len(orca.facts["jobs"]) == 3


def test_background_sensor_attempts(findings: dict[str, list[Finding]]) -> None:
    for capture in ("capture-1", "capture-2", "capture-3", "capture-4"):
        (fb,) = pick(findings[capture], "background-sensor-attempt", "com.facebook.katana")
        assert (fb.section, fb.severity, fb.app_class) == ("main", "notable", "user_installed")
        ops = {a["op"]: a for a in fb.facts["attempts"]}
        assert set(ops) == {"FINE_LOCATION", "COARSE_LOCATION"}  # never MONITOR_LOCATION
        assert ops["FINE_LOCATION"]["mode"] == "foreground"
        assert set(ops["FINE_LOCATION"]["rejected_in"]) == {"bg", "cch"}


def test_unconstrained_work_uses_the_new_definition(findings: dict[str, list[Finding]]) -> None:
    (fb,) = pick(findings["capture-2"], "unconstrained-background-work", "com.facebook.katana")
    what = {j["what"]: j for j in fb.facts["jobs"]}
    assert set(what) == {
        "NotificationsPermissionPeriodicReporter$NotificationsPermissionWorker",
        "com.facebook.media.local.UpdateLocalMediaStoreJobService",
    }
    assert what["com.facebook.media.local.UpdateLocalMediaStoreJobService"]["requires"] == [
        "TIMING_DELAY"
    ]
    # Network jobs can't be decided from capture-2 (no network class recorded).
    assert fb.facts["undetermined"] == 12
    assert "doesn't say which kind" in fb.summary


def test_hidden_from_appops_location_use_is_in_the_system_section(
    findings: dict[str, list[Finding]],
) -> None:
    hidden = [
        f
        for f in findings["capture-3"]
        if f.rule_id == "sensor-use-summary" and "requests" in f.facts
    ]
    assert {f.package for f in hidden} == {"com.google.android.gms", "android"}
    assert all(f.section == "system" and f.severity == "info" for f in hidden)


def test_system_apps_never_share_a_severity_with_user_apps(
    findings: dict[str, list[Finding]],
) -> None:
    for capture, fs in findings.items():
        for f in fs:
            assert f.severity in SEVERITIES[f.pack]
            if f.app_class == "system":
                assert (f.section, f.severity) == ("system", "info"), (
                    capture,
                    f.rule_id,
                    f.package,
                )


EXPECTED_TEXT = {
    "chatty-wakeups": "wakeups:",
    "unconstrained-background-work": "JOB ",
    "background-sensor-attempt": ("mode=", "Reject:"),
    "background-sensor-use": ("mode=", "Access:"),
    "sensor-use-summary": ("Access:", "/", "Request["),
    "over-privileged-app": ("mode=", "(allow):", "(foreground):", "Package "),
}


def test_evidence_points_at_the_raw_lines(findings: dict[str, list[Finding]]) -> None:
    """Every finding cites file + lines, and the cited lines say what it claims."""
    for capture, fs in findings.items():
        for f in fs:
            assert f.evidence, (capture, f.rule_id, f.package)
            for ref in f.evidence:
                lines = (CAPTURES / capture / ref.file).read_text().splitlines()
                assert 1 <= ref.start <= ref.end <= len(lines), ref.label
                first = lines[ref.start - 1]
                expected = EXPECTED_TEXT[f.rule_id]
                tokens = expected if isinstance(expected, tuple) else (expected,)
                assert any(t in first for t in tokens), (f.rule_id, ref.label, first[:80])
                # appops event lines sit under a `Package <pkg>:` header and don't name it.
                if f.package and ref.file != "dumpsys-appops.txt":
                    block = "\n".join(lines[ref.start - 1 : ref.end])
                    assert f.package in block or f.package == "android", (f.rule_id, ref.label)


def test_preinstalled_apps_with_an_icon_are_framed_like_installed_apps(
    findings: dict[str, list[Finding]],
) -> None:
    """capture-5 has the launcher query: Maps and Phone have icons, the platform doesn't."""
    case = CaseData(CAPTURES / "capture-5")
    assert case.classify("com.google.android.apps.maps") == "preinstalled"
    assert case.classify("com.google.android.dialer") == "preinstalled"
    for platform in ("android", "com.google.android.gms", "com.google.android.as"):
        assert case.classify(platform) == "system"
    assert case.classify("com.whatsapp") == "user_installed"
    (jobs,) = pick(findings["capture-5"], "unconstrained-background-work",
                   "com.google.android.apps.maps")  # fmt: skip
    # Background work of apps that came with the phone is info (they're listed compactly).
    assert (jobs.section, jobs.severity, jobs.app_class) == ("main", "info", "preinstalled")
    ranking = sorted(
        (f.facts["rank"], f.package)
        for f in findings["capture-5"]
        if f.rule_id == "over-privileged-app" and f.section == "main"
    )
    assert ranking[0] == (1, "com.google.android.apps.maps")
    # Without the launcher query (earlier captures) Maps stays in the system section.
    (old,) = pick(findings["capture-4"], "unconstrained-background-work",
                  "com.google.android.apps.maps")  # fmt: skip
    assert old.section == "system"


def test_background_sensor_use_maps_location(findings: dict[str, list[Finding]]) -> None:
    """Maps received precise location in the background and from a foreground service,
    with location allowed at any time (capture-5)."""
    (maps,) = pick(findings["capture-5"], "background-sensor-use", "com.google.android.apps.maps")
    assert (maps.section, maps.severity, maps.app_class) == ("main", "notable", "preinstalled")
    (use,) = maps.facts["uses"]
    assert (use["op"], use["mode"]) == ("FINE_LOCATION", "allow")
    assert use["states"] == ["bg", "cch", "fgsvc"]
    assert use["last"] == "2029-12-31 23:59:00"
    assert "MONITOR" not in str(maps.facts)
    assert "while it wasn't on screen" in maps.summary
    # A platform component goes to the system section at info.
    (asi,) = pick(findings["capture-5"], "background-sensor-use", "com.google.android.as")
    assert (asi.section, asi.severity) == ("system", "info")
    # Facebook only had refused attempts, not deliveries: nothing here.
    assert pick(findings["capture-5"], "background-sensor-use", "com.facebook.katana") == []


def test_background_microphone_severity_depends_on_visibility(tmp_path: Path) -> None:
    (tmp_path / "pm-list-packages-3p.txt").write_text(
        "package:org.example.recorder  installer=com.android.vending\n"
    )
    (tmp_path / "dumpsys-appops.txt").write_text(
        "AppOps Uid Op State\n"
        "  Uid u0a501:\n"
        "    state=cch\n"
        "    Package org.example.recorder:\n"
        "      RECORD_AUDIO (allow):\n"
        "        null=[\n"
        "          Access: [fgsvc-s] 2029-12-31 22:00:00.000 (-2h0m0s0ms) duration=+5m0s0ms\n"
        "        ]\n"
        "      FINE_LOCATION (allow):\n"
        "        null=[\n"
        "          Access: [bg-s] 2029-12-31 23:00:00.000 (-1h0m0s0ms)\n"
        "        ]\n"
        "      MONITOR_LOCATION (allow / switch COARSE_LOCATION=allow):\n"
        "        null=[\n"
        "          Access: [bg-s] 2029-12-31 23:00:00.000 (-1h0m0s0ms) duration=+3ms\n"
        "        ]\n"
    )
    case = CaseData(tmp_path)
    (spec,) = [s for s in load_rules() if s.id == "background-sensor-use"]
    (f,) = run_rules(case, [spec])
    assert case.warnings == []
    # Microphone only from a foreground service (like the Google app on a real
    # phone): notable, with the notification and indicator noted.
    assert f.severity == "notable"
    assert "only from a foreground service" in f.summary and "privacy indicator" in f.summary
    assert [u["op"] for u in f.facts["uses"]] == ["FINE_LOCATION", "RECORD_AUDIO"]
    # The same microphone delivery while cached in the background is a concern.
    appops = tmp_path / "dumpsys-appops.txt"
    appops.write_text(
        appops.read_text().replace(
            "Access: [fgsvc-s] 2029-12-31 22", "Access: [cch-s] 2029-12-31 22"
        )
    )
    case = CaseData(tmp_path)
    (f,) = run_rules(case, [spec])
    assert f.severity == "concern" and f.facts["camera_mic_in_background"] is True
    assert "foreground service" not in f.summary.split(".", 1)[1]


def test_settings_is_a_platform_component_despite_its_icon() -> None:
    case = CaseData(CAPTURES / "capture-5")
    assert "com.android.settings" in case.launcher
    assert case.classify("com.android.settings") == "system"


def test_in_use_setting_with_background_use_is_explained(tmp_path: Path) -> None:
    """Allowed "only while in use", yet used while cached: explain Android's brief
    continuation and the foreground-service allowance, so the setting doesn't look
    broken. An "allow" (any time) use gets no such note."""
    (tmp_path / "pm-list-packages-3p.txt").write_text(
        "package:org.example.walk  installer=com.android.vending\n"
    )
    appops = (
        "AppOps Uid Op State\n"
        "  Uid u0a501:\n"
        "    state=cch\n"
        "      FINE_LOCATION: mode=foreground\n"
        "    Package org.example.walk:\n"
        "      FINE_LOCATION (allow):\n"
        "        null=[\n"
        "          Access: [cch-s] 2029-12-31 23:00:00.000 (-1h0m0s0ms)\n"
        "        ]\n"
    )
    (tmp_path / "dumpsys-appops.txt").write_text(appops)
    (spec,) = [s for s in load_rules() if s.id == "background-sensor-use"]
    (f,) = run_rules(CaseData(tmp_path), [spec])
    assert f.facts["in_use_setting_background_use"] is True
    assert "only while using the app" in f.summary and "it still works" in f.summary
    assert "foreground service the app started while you were using it" in f.summary
    (tmp_path / "dumpsys-appops.txt").write_text(appops.replace("mode=foreground", "mode=allow"))
    (f,) = run_rules(CaseData(tmp_path), [spec])
    assert f.facts["in_use_setting_background_use"] is False and "it still works" not in f.summary
