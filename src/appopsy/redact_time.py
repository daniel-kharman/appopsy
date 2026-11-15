"""Time shifting for fixtures.

Access, reject, alarm and job times say when the owner used each app. Fixtures
keep the *intervals* (a reject every 5-8 minutes must still look like one) but
not the real dates: every timestamp in a capture is moved by one constant so
that the capture happens at ``ANCHOR`` (2030-01-01T00:00:00Z), and is written in
UTC.

The offset belongs to the **capture**, not the file. ``redact-fixture`` reads the
capture clock (``date-epoch.txt``, ``date-local.txt`` and the timezone from
``getprop``) during its harvest pass and shifts every file of that capture by
the same amount, so cross-file relationships and relative times such as
``(-21m14s536ms)`` stay valid. A run whose inputs contain more than one capture
clock is refused, as is a file with timestamps but no capture clock.

Device-local wall-clock times (``2027-11-12 09:15:00.250``) are converted with
the device's timezone, so events either side of a DST change keep their true
spacing; if only the ``date`` offset is known, that is used instead.

Shifted: ``YYYY-MM-DD HH:MM:SS[.fff]`` (local), year-less ``MM-DD HH:MM:SS:fff``
and ``MM-DD HH:MM:SS.fff`` (local; the year comes from the capture), dashed
``YYYY-MM-DD-HH-MM-SS`` (local),
``date`` ISO output, the
``date-epoch.txt`` epoch, 13-digit epoch milliseconds, and epoch seconds in
getprop boot times (``persist.sys.boot.reason.history``). Not shifted: values
that are the same on every device (build dates such as ``ro.build.date.utc``),
times relative to boot, and install/update times, which are normalised to
``2000-01-01 00:00:00`` outright.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from appopsy.parsers.date import EPOCH_FILENAME, LOCAL_FILENAME

# The single place the anchor is defined. It is later than any real build or
# security patch date, so ages computed in fixtures (e.g. patch age) are never
# negative.
ANCHOR = datetime(2030, 1, 1, tzinfo=UTC)
ANCHOR_EPOCH = int(ANCHOR.timestamp())
# Shifted times land just before the anchor; anything outside this window in a
# fixture was not shifted. Fixture events go back days to weeks (boot history a
# little further), so a year is ample.
EARLIEST_ALLOWED = ANCHOR - timedelta(days=365)
# Pending alarms and job deadlines are scheduled ahead (149 days seen on a Pixel 11
# Pro), so shifted times can also land after the anchor.
LATEST_ALLOWED = ANCHOR + timedelta(days=400)
# Far-future placeholders (an alarm set ~100 years out) are sentinels, not times.
SENTINEL_AFTER = ANCHOR + timedelta(days=50 * 365)

ISO_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
_ISO_LINE = re.compile(r"(?m)^(?P<v>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d{4})$")
# Device-local wall clock. Install/update times are normalised elsewhere, not shifted.
_LOCAL = re.compile(
    r"(?<![\d-])(?<!timeStamp=)(?<!lastUpdateTime=)(?<!firstInstallTime=)"
    r"(?P<d>\d{4}-\d\d-\d\d) (?P<t>\d\d:\d\d:\d\d)(?P<f>\.\d{1,6})?(?![\d:])"
)
_EPOCH_MS = re.compile(r"(?<![\d.])(?P<v>1[4-9]\d{11})(?![\d.])")
# Dashed local time, e.g. jobscheduler "Historical stats at 2027-11-12-09-15-00".
_DASHED = re.compile(
    r"(?<![\d-])(?P<d>\d{4}-\d\d-\d\d)-(?P<h>\d\d)-(?P<mi>\d\d)-(?P<s>\d\d)(?![\d-])"
)
_EPOCH_LINE = re.compile(r"(?m)^(?P<v>\d{9,11})$")
# Year-less local time with colon milliseconds, e.g. appops "Historical restrictions"
# (Do Not Disturb / Bedtime changes): `11-11 23:10:00:250`.
_MONTH_DAY = re.compile(
    r"(?<![\d-])(?P<mo>\d\d)-(?P<d>\d\d) (?P<t>\d\d:\d\d:\d\d):(?P<ms>\d{3})(?![\d:])"
)
# Year-less local time with dot milliseconds, e.g. the location event log:
# `11-12 09:14:58.123: gps provider request = ...`.
_MONTH_DAY_DOT = re.compile(
    r"(?<![\d-])(?P<mo>\d\d)-(?P<d>\d\d) (?P<t>\d\d:\d\d:\d\d)\.(?P<ms>\d{3})(?!\d)"
)
# Year-less times in fixtures should land within this window before the anchor.
MONTH_DAY_WINDOW = timedelta(days=61)
# getprop boot times that are wall-clock epoch seconds.
_BOOT_HISTORY = re.compile(r"(?ms)^\[persist\.sys\.boot\.reason\.history\]: \[(?P<v>.*?)\]$")
_BOOT_HISTORY_EPOCH = re.compile(r"(?<=,)(?P<v>\d{10})(?=\n|$)")
_GETPROP_TZ = re.compile(r"(?m)^\[persist\.sys\.timezone\]: \[(?P<v>[^\]]*)\]")


class TimeShiftError(ValueError):
    """The inputs can't be shifted consistently."""


@dataclass
class CaptureClock:
    epochs: set[int] = field(default_factory=set)
    local_offsets: set[timedelta] = field(default_factory=set)
    timezone: str | None = None
    shifted: int = 0

    def harvest(self, name: str, text: str) -> None:
        if name == EPOCH_FILENAME and (m := _EPOCH_LINE.search(text)):
            self.epochs.add(int(m["v"]))
        elif name == LOCAL_FILENAME and (m := _ISO_LINE.search(text)):
            offset = datetime.strptime(m["v"], ISO_FORMAT).utcoffset()
            if offset is not None:
                self.local_offsets.add(offset)
        elif m := _GETPROP_TZ.search(text):
            self.timezone = m["v"].strip() or None

    @property
    def epoch(self) -> int | None:
        if len(self.epochs) > 1:
            raise TimeShiftError(
                "The inputs contain more than one capture (several date-epoch.txt values). "
                "Redact one capture folder at a time."
            )
        return next(iter(self.epochs), None)

    @property
    def offset(self) -> timedelta:
        epoch = self.epoch
        if epoch is None:
            raise TimeShiftError(
                "Found timestamps but no date-epoch.txt, so there is no capture clock to "
                "shift them by. Include the capture's date files."
            )
        return timedelta(seconds=ANCHOR_EPOCH - epoch)

    def _zone(self) -> ZoneInfo | None:
        if not self.timezone:
            return None
        try:
            return ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, ValueError):
            return None

    def local_to_utc(self, local: datetime) -> datetime:
        zone = self._zone()
        if zone is not None:
            return local.replace(tzinfo=zone).astimezone(UTC)
        offset = (
            next(iter(self.local_offsets), timedelta(0))
            if len(self.local_offsets) == 1
            else timedelta(0)
        )
        return (local - offset).replace(tzinfo=UTC)

    # --- shifting ------------------------------------------------------------

    def _count(self, value: str) -> str:
        self.shifted += 1
        return value

    def _shift_local(self, m: re.Match[str]) -> str:
        frac = m["f"] or ""
        micro = int((frac[1:] + "000000")[:6]) if frac else 0
        local = datetime.strptime(f"{m['d']} {m['t']}", "%Y-%m-%d %H:%M:%S").replace(
            microsecond=micro
        )
        new = self.local_to_utc(local) + self.offset
        out = new.strftime("%Y-%m-%d %H:%M:%S")
        if frac:
            out += "." + f"{new.microsecond:06d}"[: len(frac) - 1]
        return self._count(out)

    def _shift_iso(self, m: re.Match[str]) -> str:
        instant = datetime.strptime(m["v"], ISO_FORMAT) + self.offset
        return self._count(instant.astimezone(UTC).strftime(ISO_FORMAT))

    def _capture_local(self) -> datetime:
        """The capture moment in device-local wall-clock time (naive)."""
        instant = ANCHOR - self.offset  # raises if there is no capture clock
        zone = self._zone()
        if zone is not None:
            return instant.astimezone(zone).replace(tzinfo=None)
        offset = next(iter(self.local_offsets)) if len(self.local_offsets) == 1 else timedelta(0)
        return (instant + offset).replace(tzinfo=None)

    def _shift_month_day(self, m: re.Match[str], sep: str = ":") -> str:
        capture = self._capture_local()
        stamp = f"{m['mo']}-{m['d']} {m['t']}"
        local = datetime.strptime(f"{capture.year}-{stamp}", "%Y-%m-%d %H:%M:%S")
        if local > capture + timedelta(days=1):  # e.g. a December event in a January capture
            local = local.replace(year=local.year - 1)
        local = local.replace(microsecond=int(m["ms"]) * 1000)
        new = self.local_to_utc(local) + self.offset
        return self._count(f"{new:%m-%d %H:%M:%S}{sep}{new.microsecond // 1000:03d}")

    def _shift_dashed(self, m: re.Match[str]) -> str:
        local = datetime.strptime(f"{m['d']} {m['h']}:{m['mi']}:{m['s']}", "%Y-%m-%d %H:%M:%S")
        new = self.local_to_utc(local) + self.offset
        return self._count(new.strftime("%Y-%m-%d-%H-%M-%S"))

    def shift(self, text: str, name: str = "") -> str:
        if name == EPOCH_FILENAME:
            text = _EPOCH_LINE.sub(
                lambda m: self._count(str(int(m["v"]) + int(self.offset.total_seconds()))), text
            )
            return text
        text = _ISO_LINE.sub(self._shift_iso, text)
        text = _LOCAL.sub(self._shift_local, text)
        text = _MONTH_DAY.sub(self._shift_month_day, text)
        text = _MONTH_DAY_DOT.sub(lambda m: self._shift_month_day(m, sep="."), text)
        text = _DASHED.sub(self._shift_dashed, text)
        text = _EPOCH_MS.sub(
            lambda m: self._count(str(int(m["v"]) + int(self.offset.total_seconds()) * 1000)), text
        )

        def boot_history(m: re.Match[str]) -> str:
            body = _BOOT_HISTORY_EPOCH.sub(
                lambda e: self._count(str(int(e["v"]) + int(self.offset.total_seconds()))), m["v"]
            )
            return m.group(0).replace(m["v"], body)

        return _BOOT_HISTORY.sub(boot_history, text)


def _outside_window(when: datetime) -> bool:
    """True if ``when`` (aware, or naive = UTC) can't be a shifted time."""
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return not (EARLIEST_ALLOWED <= when <= LATEST_ALLOWED or when > SENTINEL_AFTER)


def unshifted_times(text: str, name: str = "") -> list[tuple[int, str]]:
    """(line, value) for timestamps outside the window just before the anchor.

    A shifted capture puts every time in ``[EARLIEST_ALLOWED, LATEST_ALLOWED]`` (or
    beyond ``SENTINEL_AFTER``, for "never" placeholders); a real one, years before the
    anchor, falls outside. A real capture from the
    year before the anchor would pass, so this backs redaction up, it doesn't
    replace it.
    """
    found: list[tuple[int, str]] = []

    def at(pos: int) -> int:
        return text.count("\n", 0, pos) + 1

    def epoch(seconds: float) -> datetime:
        return datetime.fromtimestamp(seconds, UTC)

    if name == EPOCH_FILENAME:
        for m in _EPOCH_LINE.finditer(text):
            if _outside_window(epoch(int(m["v"]))):
                found.append((at(m.start()), m["v"]))
        return found
    for m in _ISO_LINE.finditer(text):
        if _outside_window(datetime.strptime(m["v"], ISO_FORMAT)):
            found.append((at(m.start()), m["v"]))
    for m in _LOCAL.finditer(text):
        if _outside_window(datetime.strptime(f"{m['d']} {m['t']}", "%Y-%m-%d %H:%M:%S")):
            found.append((at(m.start()), m.group(0)))
    for m in _DASHED.finditer(text):
        when = datetime.strptime(f"{m['d']} {m['h']}:{m['mi']}:{m['s']}", "%Y-%m-%d %H:%M:%S")
        if _outside_window(when):
            found.append((at(m.start()), m.group(0)))
    for m in [*_MONTH_DAY.finditer(text), *_MONTH_DAY_DOT.finditer(text)]:
        # No year: read it as the date closest before the anchor and require it to
        # fall in the shorter window for year-less times.
        month, day = int(m["mo"]), int(m["d"])
        year = ANCHOR.year if month == ANCHOR.month else ANCHOR.year - 1
        try:
            when = datetime(year, month, day, tzinfo=UTC)
        except ValueError:
            continue
        if not (ANCHOR - MONTH_DAY_WINDOW <= when <= LATEST_ALLOWED):
            found.append((at(m.start()), m.group(0)))
    for m in _EPOCH_MS.finditer(text):
        if _outside_window(epoch(int(m["v"]) / 1000)):
            found.append((at(m.start()), m["v"]))
    for m in _BOOT_HISTORY.finditer(text):
        for e in _BOOT_HISTORY_EPOCH.finditer(m["v"]):
            if _outside_window(epoch(int(e["v"]))):
                found.append((at(m.start()), e["v"]))
    return found
