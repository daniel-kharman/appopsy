"""Rules engine.

A rule is two things:

- a **YAML spec** in ``rules/<pack>/<id>.yaml``: id, pack, title, severity,
  description, rationale, benign explanations, remediation, and thresholds, each
  with the source it comes from. It names its function by id. There is no
  condition language: YAML says *what* and *why*, never *how*.
- a **registered, typed Python function** (``@rule_function("<id>", thresholds=...)``)
  that reads parsed case data and returns findings.

Loading checks that the pack's severity scale is respected (privacy: info /
notable / concern; security: low / medium / high / critical), that every
threshold cites a source, and that the spec's thresholds are exactly the ones its
function declares. System apps are framed centrally (see :func:`make_finding`):
their findings go to the "system" section at the lowest severity, never alongside
user-installed apps.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import date
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

if TYPE_CHECKING:
    from appopsy.rules.case import CaseData

Pack = Literal["privacy", "security"]
SEVERITIES: dict[str, tuple[str, ...]] = {
    "privacy": ("info", "notable", "concern"),
    "security": ("low", "medium", "high", "critical"),
}
# preinstalled: came with the phone and has a launcher icon (Maps, Phone); ranked and
# framed like installed apps. system: platform components without an icon.
AppClass = Literal["user_installed", "preinstalled", "system", "unknown"]
Section = Literal["main", "system"]
# Specs ship inside the package (appopsy/rules/specs/<pack>/<id>.yaml), so an
# installed appopsy finds them without the repo.
RULES_DIR: Traversable = resources.files("appopsy.rules") / "specs"


class RuleError(ValueError):
    """A rule spec is invalid or doesn't match its function."""


class ThresholdSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str
    url: str | None = None
    checked: date  # when the figure was last checked against the source
    verified: bool  # False: the figure couldn't be confirmed from the source itself
    quote: str | None = None
    note: str | None = None


class MethodSource(BaseModel):
    """Why a rule has no threshold, or where its method comes from."""

    model_config = ConfigDict(extra="forbid")

    title: str
    checked: date
    note: str


class Threshold(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: float
    unit: str
    source: ThresholdSource


class RuleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
    pack: Pack
    title: str
    severity: str
    function: str
    description: str
    rationale: str
    benign_explanations: list[str] = Field(min_length=1)
    remediation: list[str] = Field(min_length=1)
    thresholds: dict[str, Threshold] = {}
    source: MethodSource | None = None  # e.g. "no external source for a cut-off"
    # Other levels the rule's function may assign per finding (e.g. concern for the
    # microphone, notable for location); `severity` is the default. Same pack scale.
    severities: list[str] = []

    @model_validator(mode="after")
    def _severity_matches_pack(self) -> RuleSpec:
        scale = SEVERITIES[self.pack]
        for severity in (self.severity, *self.severities):
            if severity not in scale:
                raise ValueError(f"severity {severity!r} is not on the {self.pack} scale {scale}")
        return self

    @property
    def allowed_severities(self) -> set[str]:
        return {self.severity, *self.severities}

    def threshold(self, name: str) -> float:
        return self.thresholds[name].value


class EvidenceRef(BaseModel):
    """Raw lines in the case folder that a finding rests on."""

    file: str  # file name in the case's raw/ folder
    start: int
    end: int

    @property
    def label(self) -> str:
        return (
            f"{self.file}:{self.start}"
            if self.start == self.end
            else f"{self.file}:{self.start}-{self.end}"
        )


class Finding(BaseModel):
    rule_id: str
    pack: Pack
    severity: str
    title: str
    package: str | None = None
    app_class: AppClass = "unknown"
    section: Section = "main"
    summary: str
    facts: dict[str, Any] = {}
    evidence: list[EvidenceRef] = []


RuleFunction = Callable[["CaseData", RuleSpec], list[Finding]]


@dataclass(frozen=True)
class RegisteredRule:
    function: RuleFunction
    thresholds: frozenset[str]


_REGISTRY: dict[str, RegisteredRule] = {}


def rule_function(
    function_id: str, *, thresholds: Iterable[str] = ()
) -> Callable[[RuleFunction], RuleFunction]:
    """Register a rule function under ``function_id`` with the thresholds it reads."""

    def register(fn: RuleFunction) -> RuleFunction:
        if function_id in _REGISTRY:
            raise RuleError(f"rule function {function_id!r} registered twice")
        _REGISTRY[function_id] = RegisteredRule(fn, frozenset(thresholds))
        return fn

    return register


def registered() -> dict[str, RegisteredRule]:
    _import_rule_modules()
    return dict(_REGISTRY)


def _import_rule_modules() -> None:
    import appopsy.rules.privacy  # noqa: F401  (registers the privacy functions)


def load_rule(path: Traversable, folder: str | None = None) -> RuleSpec:
    """Load one spec. ``folder`` is the pack folder it is in (from the path if a Path)."""
    if folder is None:
        folder = path.parent.name if isinstance(path, Path) else ""
    _import_rule_modules()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        spec = RuleSpec.model_validate(data)
    except (yaml.YAMLError, ValidationError) as exc:
        raise RuleError(f"{path}: {exc}") from exc
    if spec.id != path.name.removesuffix(".yaml"):
        raise RuleError(f"{path}: id {spec.id!r} doesn't match the file name")
    if spec.pack != folder:
        raise RuleError(f"{path}: pack {spec.pack!r} but the file is in the {folder!r} folder")
    reg = _REGISTRY.get(spec.function)
    if reg is None:
        raise RuleError(f"{path}: no registered rule function {spec.function!r}")
    if set(spec.thresholds) != reg.thresholds:
        raise RuleError(
            f"{path}: thresholds {sorted(spec.thresholds)} don't match what "
            f"{spec.function!r} reads: {sorted(reg.thresholds)}"
        )
    return spec


def load_rules(
    directory: Traversable = RULES_DIR, packs: Iterable[str] = ("privacy", "security")
) -> list[RuleSpec]:
    specs: list[RuleSpec] = []
    for pack in packs:
        folder = directory / pack
        if not folder.is_dir():
            continue
        files = sorted((f for f in folder.iterdir() if f.name.endswith(".yaml")), key=str)
        specs += [load_rule(f, pack) for f in files]
    ids = [s.id for s in specs]
    if len(ids) != len(set(ids)):
        raise RuleError(f"duplicate rule ids: {sorted({i for i in ids if ids.count(i) > 1})}")
    return specs


def run_rules(case: CaseData, specs: Iterable[RuleSpec]) -> list[Finding]:
    findings: list[Finding] = []
    for spec in specs:
        findings += _REGISTRY[spec.function].function(case, spec)
    return findings


def make_finding(
    spec: RuleSpec,
    case: CaseData,
    package: str | None,
    summary: str,
    *,
    facts: dict[str, Any] | None = None,
    evidence: list[EvidenceRef] | None = None,
    force_system: bool = False,
    severity: str | None = None,
) -> Finding:
    """Build a finding, framing system apps: their own section, lowest severity.

    ``severity`` overrides the spec's default with one the spec lists in `severities`.
    """
    if severity is not None and severity not in spec.allowed_severities:
        raise RuleError(f"{spec.id}: severity {severity!r} isn't declared in its spec")
    app_class: AppClass = case.classify(package) if package else "unknown"
    system = force_system or app_class == "system"
    return Finding(
        rule_id=spec.id,
        pack=spec.pack,
        severity=SEVERITIES[spec.pack][0] if system else (severity or spec.severity),
        title=spec.title,
        package=package,
        app_class=app_class,
        section="system" if system else "main",
        summary=summary,
        facts=facts or {},
        evidence=evidence or [],
    )
