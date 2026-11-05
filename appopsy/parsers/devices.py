"""Parser for `adb devices -l`."""

from __future__ import annotations

import re

from pydantic import BaseModel

from appopsy.parsers.base import ParseWarning

SOURCE = "adb devices -l"

_HEADER = "List of devices attached"
# Trailing key:value attributes. The state itself can contain spaces
# ("no permissions (...); see [http://...]"), so these are peeled off the end.
_ATTR = re.compile(r"(usb|product|model|device|transport_id):(\S+)")


class Device(BaseModel):
    serial: str
    state: str
    usb: str | None = None
    product: str | None = None
    model: str | None = None
    device: str | None = None
    transport_id: str | None = None

    @property
    def ready(self) -> bool:
        """True when adb can run commands on the device."""
        return self.state == "device"

    @property
    def display_model(self) -> str | None:
        return self.model.replace("_", " ") if self.model else None


def parse_devices(text: str) -> tuple[list[Device], list[ParseWarning]]:
    devices: list[Device] = []
    warnings: list[ParseWarning] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line == _HEADER or line.startswith("* daemon") or line.startswith("adb "):
            continue
        parts = line.split()
        if len(parts) < 2:
            warnings.append(
                ParseWarning(source=SOURCE, line=lineno, text=raw, message="no device state")
            )
            continue
        serial, rest = parts[0], parts[1:]
        attrs: dict[str, str] = {}
        while rest and (m := _ATTR.fullmatch(rest[-1])):
            attrs[m.group(1)] = m.group(2)
            rest.pop()
        if not rest:
            warnings.append(
                ParseWarning(source=SOURCE, line=lineno, text=raw, message="no device state")
            )
            continue
        devices.append(Device(serial=serial, state=" ".join(rest), **attrs))
    return devices, warnings
