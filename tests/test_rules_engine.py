"""Rule specs: schema, severity scales, threshold sources, function binding."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from appopsy.rules.engine import RULES_DIR, SEVERITIES, RuleError, load_rule, load_rules, registered

VALID = {
    "id": "chatty-wakeups",
    "pack": "privacy",
    "title": "t",
    "severity": "notable",
    "function": "chatty-wakeups",
    "description": "d",
    "rationale": "r",
    "benign_explanations": ["b"],
    "remediation": ["x"],
    "thresholds": {
        "wakeups_per_hour": {
            "value": 10,
            "unit": "per hour",
            "source": {"title": "s", "checked": "2026-10-30", "verified": True},
        }
    },
}


def write(
    tmp_path: Path, data: dict[str, object], pack: str = "privacy", name: str | None = None
) -> Path:
    path = tmp_path / pack / f"{name or data['id']}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data))
    return path


def test_repository_rules_load_and_every_threshold_cites_a_source() -> None:
    specs = load_rules()
    assert {s.id for s in specs} >= {
        "background-sensor-attempt", "chatty-wakeups", "sensor-use-summary",
        "unconstrained-background-work",
    }  # fmt: skip
    for spec in specs:
        assert spec.severity in SEVERITIES[spec.pack]
        for name, threshold in spec.thresholds.items():
            assert threshold.source.title and threshold.source.checked, (spec.id, name)
            if not threshold.source.verified:
                assert threshold.source.note, f"{spec.id}.{name}: unverified source needs a note"


def test_valid_spec_loads(tmp_path: Path) -> None:
    assert load_rule(write(tmp_path, VALID)).threshold("wakeups_per_hour") == 10


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"severity": "high"}, "not on the privacy scale"),  # a security label on a privacy rule
        ({"severities": ["critical"]}, "not on the privacy scale"),  # extra levels too
        ({"pack": "security", "severity": "concern"}, "not on the security scale"),
        ({"function": "no-such-rule"}, "no registered rule function"),
        ({"thresholds": {}}, "don't match what"),
        ({"thresholds": {"wakeups_per_hour": {"value": 10, "unit": "h"}}}, "source"),
        ({"condition": "wakeups > 10"}, "Extra inputs"),  # no condition language
        ({"benign_explanations": []}, "at least 1"),
    ],
)
def test_invalid_specs_are_refused(tmp_path: Path, change: dict[str, object], message: str) -> None:
    data = {**VALID, **change}
    pack = str(data["pack"])
    with pytest.raises(RuleError, match=message):
        load_rule(write(tmp_path, data, pack=pack))


def test_file_name_and_folder_must_match(tmp_path: Path) -> None:
    with pytest.raises(RuleError, match="doesn't match the file name"):
        load_rule(write(tmp_path, VALID, name="other-name"))
    with pytest.raises(RuleError, match="in the 'security' folder"):
        load_rule(write(tmp_path, VALID, pack="security"))


def test_every_registered_function_has_a_spec() -> None:
    used = {s.function for s in load_rules(RULES_DIR)}
    assert set(registered()) == used


def test_a_finding_may_only_use_severities_its_spec_declares(tmp_path: Path) -> None:
    from appopsy.rules.case import CaseData
    from appopsy.rules.engine import make_finding

    spec = load_rule(write(tmp_path, {**VALID, "severities": ["concern"]}, pack="privacy"))
    case = CaseData(tmp_path)
    assert (
        make_finding(spec, case, "com.example.app", "s", severity="concern").severity == "concern"
    )
    assert make_finding(spec, case, "com.example.app", "s").severity == spec.severity
    with pytest.raises(RuleError, match="isn't declared"):
        make_finding(spec, case, "com.example.app", "s", severity="info")
