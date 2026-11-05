from __future__ import annotations

from collections.abc import Callable

import pytest

from appopsy.adb import Adb, RunResult


class FakeRunner:
    """Stands in for subprocess. Maps adb args (after the executable) to output."""

    def __init__(self, responses: dict[tuple[str, ...], str | RunResult] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], timeout: float) -> RunResult:
        self.calls.append(argv)
        key = tuple(argv[1:])
        response = self.responses.get(key, "")
        if isinstance(response, RunResult):
            return response
        return RunResult(0, response, "")


@pytest.fixture
def fake_runner() -> FakeRunner:
    return FakeRunner()


@pytest.fixture
def make_fake_adb() -> Callable[..., tuple[Adb, FakeRunner]]:
    def _make(
        responses: dict[tuple[str, ...], str | RunResult] | None = None,
        serial: str | None = "SERIAL123",
    ) -> tuple[Adb, FakeRunner]:
        runner = FakeRunner(responses)
        return Adb(serial, runner=runner), runner

    return _make
