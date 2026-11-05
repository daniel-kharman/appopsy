from __future__ import annotations

import pytest

from appopsy.adb import DeviceSelectionError, select_device
from appopsy.parsers.devices import Device, parse_devices

# Synthetic `adb devices -l` output covering the states adb reports.
DEVICES_OUTPUT = """\
* daemon not running; starting now at tcp:5037
* daemon started successfully
List of devices attached
FAKESERIAL01           device usb:1-1 product:grizzly model:Pixel_11_Pro device:grizzly transport_id:1
FAKESERIAL02           unauthorized usb:1-2 transport_id:2
192.168.0.10:5555      offline product:a54x model:SM_A546B device:a54x transport_id:3
FAKESERIAL03           no permissions (missing udev rules? user is in the plugdev group); see [http://developer.android.com/tools/device.html] usb:1-3 transport_id:4
adb-FAKE04-AbCdEf._adb-tls-connect._tcp device product:husky model:Pixel_8_Pro device:husky transport_id:5
GARBAGE
"""


def test_parse_devices_states_and_attributes() -> None:
    devices, warnings = parse_devices(DEVICES_OUTPUT)
    by_serial = {d.serial: d for d in devices}

    pixel = by_serial["FAKESERIAL01"]
    assert pixel.ready
    assert pixel.model == "Pixel_11_Pro"
    assert pixel.display_model == "Pixel 11 Pro"
    assert pixel.product == "grizzly"
    assert pixel.transport_id == "1"

    assert by_serial["FAKESERIAL02"].state == "unauthorized"
    assert not by_serial["FAKESERIAL02"].ready
    assert by_serial["192.168.0.10:5555"].state == "offline"
    assert by_serial["FAKESERIAL03"].state.startswith("no permissions")
    assert by_serial["FAKESERIAL03"].usb == "1-3"
    assert by_serial["adb-FAKE04-AbCdEf._adb-tls-connect._tcp"].ready

    assert len(devices) == 5
    assert [w.text for w in warnings] == ["GARBAGE"]


def test_parse_empty_list() -> None:
    assert parse_devices("List of devices attached\n\n") == ([], [])


def _dev(serial: str, state: str = "device") -> Device:
    return Device(serial=serial, state=state)


def test_select_single_ready_device() -> None:
    assert select_device([_dev("A"), _dev("B", "unauthorized")]).serial == "A"


def test_select_requires_serial_when_several_ready() -> None:
    with pytest.raises(DeviceSelectionError, match="--serial"):
        select_device([_dev("A"), _dev("B")])


def test_select_by_serial() -> None:
    assert select_device([_dev("A"), _dev("B")], serial="B").serial == "B"


def test_select_unknown_serial() -> None:
    with pytest.raises(DeviceSelectionError, match="No device with serial Z"):
        select_device([_dev("A")], serial="Z")


def test_select_unauthorized_gives_hint() -> None:
    with pytest.raises(DeviceSelectionError, match="Allow USB debugging"):
        select_device([_dev("A", "unauthorized")])


def test_select_no_devices() -> None:
    with pytest.raises(DeviceSelectionError, match="No devices found"):
        select_device([])
