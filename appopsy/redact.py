"""Redaction of personal identifiers from raw adb output.

Used by ``appopsy redact-fixture`` (before a dump becomes a test fixture) and by
the fixture scanner in CI. Both use the same detectors, so anything the scanner
would flag is something the redactor replaces.

Replacement is *consistent*: one :class:`Redactor` maps each distinct original
value to one placeholder, across every file it processes. A serial that shows up
in ``getprop`` and in ``dumpsys`` becomes the same ``FAKESERIAL0001`` in both, so
cross-file relationships survive redaction.

Placeholders keep the shape of the original (a MAC stays a MAC, an IPv4 address
stays an IPv4 address) so parsers still work on redacted fixtures, and they come
from reserved or obviously fake ranges (example.com, 192.0.2.0/24, 2001:db8::/32,
locally administered MACs, the +1 555-01xx fictional numbers, MCC 001 test
networks). Redaction is idempotent: placeholders are recognised and left alone.

Some values aren't identifiers but still say where the owner lives or is: the
timezone, the locale and the device's UTC offset. These are *neutralised*
rather than numbered: every timezone becomes ``Etc/UTC``, every locale ``en-US``,
and a ``date`` local timestamp is rewritten as the same instant in UTC
(``+0000``) so it still agrees with the epoch.

Installed packages are handled by :mod:`appopsy.redact_packages`: system
packages stay, and the only third-party packages left are a fixed allowlist.

**General rule: any value that is random or assigned per device or per install
is normalised**, even when it isn't obviously personal, because it can link a
fixture back to one phone. Examples: hardware IDs (``ro.boot.hw.soc.id``,
``vendor.modem.soc_id``), install/update timestamps, the random
``/data/app/~~<base64>==`` segments, domain-verification IDs, theme overlay
(``.frro``) suffixes, data-directory inode numbers and signing keyset IDs.
Values that change on every boot (object hashes such as ``Package{f39ba71 ...}``,
``cache_key.*`` properties) can't link anything and are kept; values shared by
every device on a build (fingerprints, partition digests, build UUIDs) are kept.
App UIDs are kept because rules join appops to packages by UID.
"""

from __future__ import annotations

import functools
import re
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from appopsy.collectors.alarm import FILENAME as ALARM_FILENAME
from appopsy.collectors.jobscheduler import FILENAME as JOBSCHEDULER_FILENAME
from appopsy.collectors.launcher import FILENAME as LAUNCHER_FILENAME
from appopsy.gitfiles import committable
from appopsy.redact_packages import (
    DEFAULT_ALLOWLIST,
    AllowedPackage,
    PackagePolicy,
    policy_for_tree,
)
from appopsy.redact_time import CaptureClock, unshifted_times
from appopsy.report import app_names

# --- Validators -------------------------------------------------------------


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _luhn_complete(body: str) -> str:
    """Append the Luhn check digit to ``body``."""
    for check in "0123456789":
        if luhn_ok(body + check):
            return body + check
    raise AssertionError("unreachable")


# Reporting-body prefixes seen on real IMEIs. Limiting unlabelled 15-digit
# matches to these keeps nanosecond timestamps from being flagged.
_IMEI_PREFIXES = {"01", "10", "30", "33", "35", "44", "45", "49", "50", "51", "52", "53", "54",
                  "86", "91", "98", "99"}  # fmt: skip


def _imei_unlabelled(value: str) -> bool:
    return value[:2] in _IMEI_PREFIXES and luhn_ok(value)


def _mac_ok(value: str) -> bool:
    norm = value.lower().replace("-", ":")
    return norm not in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "02:00:00:00:00:00"}


def _ipv4_ok(value: str) -> bool:
    octets = [int(o) for o in value.split(".")]
    if any(o > 255 for o in octets):
        return False
    return not (octets[0] in {0, 127, 255} or value == "255.255.255.255")


def _ipv6_ok(value: str) -> bool:
    return value.lower() not in {"::", "::1"} and len(value) >= 6


def _coords_ok(lat: str, lon: str) -> bool:
    return abs(float(lat)) <= 90 and abs(float(lon)) <= 180 and (float(lat), float(lon)) != (0, 0)


# --- Placeholders -----------------------------------------------------------


def _ipv4_placeholder(n: int) -> str:
    nets = ["192.0.2", "198.51.100", "203.0.113"]  # RFC 5737 documentation ranges
    net, host = divmod(n - 1, 254)
    return f"{nets[net % 3]}.{host + 1}"


PLACEHOLDERS: dict[str, Callable[[int], str]] = {
    "email": lambda n: f"user{n}@example.com",
    "phone": lambda n: f"+1202555{100 + n:04d}",
    "imei": lambda n: _luhn_complete(f"{n:014d}"),
    "iccid": lambda n: _luhn_complete(f"8900000000{n:08d}"),
    "mac": lambda n: f"02:00:00:00:{n >> 8 & 0xFF:02x}:{n & 0xFF:02x}",
    "ipv4": _ipv4_placeholder,
    "ipv6": lambda n: f"2001:db8::{n:x}",
    "ssid": lambda n: f"ssid-{n}",
    "account": lambda n: f"account-{n}",
    "coords": lambda n: f"{n % 90}.000000,{n % 180}.000000",
    "serial": lambda n: f"FAKESERIAL{n:04d}",
    "android_id": lambda n: f"{n:016x}",
    "carrier": lambda n: f"carrier-{n}",
    "mccmnc": lambda n: f"001{n:02d}",
    "country": lambda n: "xx",
    "device_id": lambda n: f"REDACTED-ID-{n}",
    "uuid": lambda n: f"00000000-0000-0000-0000-{n:012d}",
}

# A value matching one of these is already a placeholder and is left alone.
_IS_PLACEHOLDER: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[^@\s]+@example\.(?:com|org|net)", re.I),
    "phone": re.compile(r"\+1\d{3}55501\d\d"),
    "imei": re.compile(r"0{8}\d{7}"),
    "iccid": re.compile(r"89000000000\d{8}"),
    "mac": re.compile(r"02[:-]00[:-]00[:-]00[:-][0-9a-f]{2}[:-][0-9a-f]{2}", re.I),
    "ipv4": re.compile(r"(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}"),
    "ipv6": re.compile(r"2001:db8:[0-9a-f:]*", re.I),
    "ssid": re.compile(r"ssid-\d+|<unknown ssid>|"),
    "account": re.compile(r"account-\d+"),
    "coords": re.compile(r"\d{1,3}\.0+,\d{1,3}\.0+"),
    "serial": re.compile(r"FAKESERIAL\d+"),
    "android_id": re.compile(r"0{8}[0-9a-f]{8}"),
    "carrier": re.compile(r"carrier-\d+|"),
    "mccmnc": re.compile(r"001\d\d|"),
    "country": re.compile(r"xx|"),
    "device_id": re.compile(r"REDACTED-ID-\d+"),
    "uuid": re.compile(r"00000000-0000-0000-0000-\d{12}"),
}


def is_placeholder(category: str, value: str) -> bool:
    pattern = _IS_PLACEHOLDER.get(category)
    return bool(pattern and pattern.fullmatch(value))


# --- Detectors --------------------------------------------------------------


@dataclass(frozen=True)
class Detector:
    """Finds one kind of identifier. ``group`` names the part of the match to replace."""

    category: str
    pattern: re.Pattern[str]
    group: int | str = 0
    validate: Callable[[str], bool] = lambda _v: True
    split: str | None = None  # replace each element of a delimited list separately
    fixed: str | None = None  # neutralise: any other value becomes this
    transform: Callable[[str], str] | None = None  # neutralise: rewrite the value
    scan: bool = True  # whether the fixture scanner reports it


_LOCAL_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


INSTALL_TIME = "2000-01-01 00:00:00"
_RANDOM_SEGMENT = re.compile(r"(?<=~~)[A-Za-z0-9_-]+(?===)|(?<=-)[A-Za-z0-9_-]{16,}(?===)")


def _normalise_app_path(value: str) -> str:
    """``~~M-CM9P...==/com.x-QsZs...==`` -> ``~~REDACTED==/com.x-REDACTED==`` (random per install)."""
    return _RANDOM_SEGMENT.sub("REDACTED", value)


_GETPROP = r"^\[(?:{key})\]: \[(?P<v>[^\]\n]*)\]"
# getprop keys holding per-chip hardware identifiers.
_HW_ID_KEYS = r"[\w.]*(?:soc[._]id|chip[._]?id|cdt_hwid)"
FRRO_SUFFIX = "XXXX"

DETECTORS: tuple[Detector, ...] = (
    # Not `x@pkg.name/...` (WorkManager tags: `#Worker#@androidx.work.systemjobscheduler@pkg/`).
    Detector("email", re.compile(r"(?<![\w.+@-])[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w/@-])")),
    Detector("account", re.compile(r"Account\s*\{name=(?P<v>[^,}]+),"), "v"),
    Detector("phone", re.compile(r"(?<![\w+])\+[1-9]\d{7,14}(?![\w])")),
    Detector("phone", re.compile(r"(?i)\b(?:tel:|msisdn[=:]\s*|line1Number[=:]\s*|phoneNumber[=:]\s*)(?P<v>\+?\d[\d -]{5,}\d)"), "v"),
    Detector("iccid", re.compile(r"(?i)\biccid\w*\]?\s*[=:]\s*\[?(?P<v>\d{6,22})"), "v"),
    Detector("iccid", re.compile(r"(?<!\d)89\d{17,18}(?!\d)"), validate=luhn_ok),
    Detector("imei", re.compile(r"(?i)\b(?:imei|meid|imsi)\w*\]?\s*[=:]\s*\[?(?P<v>[0-9A-Fa-f]{14,16})(?![0-9A-Fa-f])"), "v"),
    Detector("imei", re.compile(r"(?<!\d)\d{15}(?!\d)"), validate=_imei_unlabelled),
    Detector("mac", re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}([:-]))(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])"), validate=_mac_ok),
    Detector("ipv6", re.compile(r"(?i)(?<![\w:])(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}(?![\w:])"), validate=_ipv6_ok),
    Detector("ipv6", re.compile(r"(?i)(?<![\w:])(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,5})?(?![\w:])"), validate=_ipv6_ok),
    Detector("ipv4", re.compile(r"(?<![\w.])(?<!ersion[=:])(?<!ersionName=)(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"), validate=_ipv4_ok),
    Detector("ssid", re.compile(r"(?i)(?<![A-Za-z])SSID[=:]\s*\"(?P<v>[^\"\n]*)\""), "v"),
    Detector("ssid", re.compile(r"(?i)(?<![A-Za-z])SSID[=:]\s*(?P<v>[^\s,\"\]}]+)"), "v"),
    Detector("coords", re.compile(r"(?<![\d.])-?\d{1,3}\.\d{4,},\s?-?\d{1,3}\.\d{4,}(?![\d.])")),
    # Any other coordinate-shaped pair (space, ';' or '/' between), and labelled
    # latitude/longitude values, wherever they appear.
    Detector("coords", re.compile(r"(?<![\d.])[-+]?\d{1,3}\.\d{4,}(?:\s*[;/]\s*|\s+)[-+]?\d{1,3}\.\d{4,}(?![\d.])")),
    Detector("coords_label", re.compile(r"(?i)\b(?:lat|latitude|lon|lng|long|longitude)\s*[=:]\s*(?P<v>[-+]?\d{1,3}\.\d{2,})"), "v", fixed="0.0"),
    Detector("serial", re.compile(r"(?i)serial(?:no|number|_number)?\]?\s*[=:]\s*\[?(?P<v>[A-Za-z0-9]{6,20})(?![A-Za-z0-9])"), "v"),
    Detector("serial", re.compile(r"(?m)^(?P<v>[A-Za-z0-9]{8,20})[ \t]+(?:device|unauthorized|offline|recovery|sideload|bootloader)\b"), "v"),
    Detector("android_id", re.compile(r"(?i)android[_ ]?id\]?\s*[=:]\s*\[?(?P<v>[0-9a-f]{16})(?![0-9a-f])"), "v"),
    Detector("carrier", re.compile(_GETPROP.format(key=r"gsm\.(?:sim\.)?operator\.alpha"), re.M), "v", split=","),
    Detector("mccmnc", re.compile(_GETPROP.format(key=r"gsm\.(?:sim\.)?(?:apn\.sim\.)?operator\.numeric"), re.M), "v", split=","),
    Detector("country", re.compile(_GETPROP.format(key=r"gsm\.(?:sim\.)?operator\.iso-country"), re.M), "v", split=","),
    Detector("timezone", re.compile(_GETPROP.format(key=r"persist\.sys\.timezone"), re.M), "v", fixed="Etc/UTC"),
    Detector("locale", re.compile(_GETPROP.format(key=r"persist\.sys\.locale|ro\.product\.locale"), re.M), "v", fixed="en-US"),
    Detector("locale", re.compile(_GETPROP.format(key=r"persist\.sys\.language|ro\.product\.locale\.language"), re.M), "v", fixed="en"),
    Detector("locale", re.compile(_GETPROP.format(key=r"persist\.sys\.country|ro\.product\.locale\.region"), re.M), "v", fixed="US"),
    Detector("locale", re.compile(_GETPROP.format(key=r"persist\.sys\.localevar"), re.M), "v", fixed=""),
    # `date +%Y-%m-%dT%H:%M:%S%z` output: a whole line. Not scanned, so a
    # synthetic fixture can keep a non-zero offset to exercise time conversion;
    # the timezone property, which pins the offset down, is scanned.
    # dumpsys package: when this phone installed/updated the app, and per-install randomness.
    Detector("install_time", re.compile(r"\b(?:timeStamp|lastUpdateTime|firstInstallTime)=(?P<v>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)"), "v", fixed=INSTALL_TIME),
    Detector("app_path", re.compile(r"/data/app/(?P<v>~~[A-Za-z0-9_-]+==/[A-Za-z][\w.]*-[A-Za-z0-9_-]+==)"), "v", transform=_normalise_app_path),
    Detector("device_id", re.compile(_GETPROP.format(key=_HW_ID_KEYS), re.M), "v"),
    # Carrier IDs inside property names (`setupwizard.feature.x.carrier1234`) identify
    # the carrier like the gsm.operator.* values do.
    Detector("carrier_id", re.compile(r"(?m)^\[[^\]\s]*\.carrier(?P<v>\d+)\]"), "v", fixed="0"),
    # A per-device date (before the build date: likely when the phone was set up).
    Detector("setup_date", re.compile(_GETPROP.format(key=r"com\.google\.android\.setupwizard\.complianceDate"), re.M), "v", fixed="2000-01-01"),
    Detector("overlay_suffix", re.compile(r"/data/resource-cache/[\w.]+-[\w]+-(?P<v>[A-Za-z0-9]+)\.frro\b"), "v", fixed=FRRO_SUFFIX),
    Detector("inode", re.compile(r"\b(?:ce|de|pccCe|pccDe)DataInode=(?P<v>\d+)"), "v", fixed="0"),
    Detector("keyset", re.compile(r"\bSigning KeySets: (?P<v>[\d, ]*\d)"), "v", fixed="1"),
    # jobscheduler job extras: free-form app data (account names, user IDs, ...). No
    # rule needs them, so non-empty bundles become {REDACTED}.
    Detector("job_extras", re.compile(r"(?m)^\s+(?:Transient extras|Extras): \{(?P<v>.+)\}$"), "v", fixed="REDACTED"),
    Detector("uuid", re.compile(r"(?m)^\s+ID: (?P<v>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"), "v"),
)  # fmt: skip

# getprop keys whose values are device-unique. They are harvested from every
# input file first, then replaced as literals everywhere (they may appear in
# other dumps without a label).
SEED_KEYS: dict[str, re.Pattern[str]] = {
    "serial": re.compile(r"ro\.(?:boot\.)?serialno"),
    "device_id": re.compile(
        r"ro\.boot\.vbmeta\.device|gsm\.sim\.preiccid_\d+|persist\.sys\.device_name"
        r"|net\.hostname|ro\.boot\.cpuid|ro\.boot\.ap_serial|" + _HW_ID_KEYS
    ),
}
_SEED_LINE = re.compile(r"^\[(?P<k>[^\]]+)\]: \[(?P<v>[^\]\n]*)\]", re.M)
# Seed values too generic to replace as literals.
_SEED_SKIP = {"", "unknown", "android", "localhost", "0", "1"}


def _coords_valid(value: str) -> bool:
    parts = [p for p in re.split(r"[,;/\s]+", value.strip()) if p]
    if len(parts) != 2:
        return False
    return _coords_ok(parts[0], parts[1])


_VALIDATORS_OVERRIDE = {"coords": _coords_valid}


@dataclass(frozen=True)
class Finding:
    category: str
    value: str
    line: int


def _matches(text: str) -> Iterator[tuple[Detector, re.Match[str]]]:
    for det in DETECTORS:
        for m in det.pattern.finditer(text):
            yield det, m


def _elements(det: Detector, value: str) -> list[str]:
    return value.split(det.split) if det.split else [value]


def _is_personal(det: Detector, value: str) -> bool:
    if det.fixed is not None:
        return value != det.fixed
    if det.transform is not None:
        return det.transform(value) != value
    validate = _VALIDATORS_OVERRIDE.get(det.category, det.validate)
    return bool(value) and not is_placeholder(det.category, value) and validate(value)


# Network details (jobscheduler and elsewhere): available networks, transports,
# NetworkRequest capability lists and network ids. No rule needs them and they can
# reveal VPN use and the VPN app's UID, so they are dropped from fixtures.
_NETWORK_LINE = re.compile(
    r"NetworkRequest \[|\bCNM\{|\bTransports: |^\s+Network: \d+\s*$"
    r"|^\s+Subscription ID signal strengths:"
)
_NETWORK_SECTIONS = ("ConnectivityController:",)


def _network_lines(lines: list[str]) -> list[int]:
    """Indexes of network-detail lines, including their more-indented lines."""
    hits: list[int] = []
    in_section = False
    skip: int | None = None
    for i, raw in enumerate(lines):
        line = raw.rstrip("\n")
        if line.strip() and not line[0].isspace():
            in_section = line.rstrip() in _NETWORK_SECTIONS
            skip = None
            continue
        if not line.strip():
            continue
        if in_section or (skip is not None and len(line) - len(line.lstrip()) > skip):
            hits.append(i)
        elif _NETWORK_LINE.search(line):
            hits.append(i)
            skip = len(line) - len(line.lstrip())
        else:
            skip = None
    return hits


# A job's network requirement is a rule input (unmetered vs any network), but the
# NetworkRequest itself lists capabilities and transports (VPN use). Keep only the
# class: `Network type: unmetered` or `Network type: any`.
_JOB_NETWORK_TYPE = re.compile(r"(?m)^(?P<pre>\s+Network type: )NetworkRequest \[.*$")


def _network_class(m: re.Match[str]) -> str:
    return m["pre"] + ("unmetered" if "NOT_METERED" in m.group(0) else "any")


def drop_network_details(text: str) -> tuple[str, int]:
    text = _JOB_NETWORK_TYPE.sub(_network_class, text)
    lines = text.splitlines(keepends=True)
    hits = set(_network_lines(lines))
    return "".join(line for i, line in enumerate(lines) if i not in hits), len(hits)


# jobscheduler job IDs: `<uid label or number>/<id>`. App-chosen (often a per-install
# counter), so replaced with small numbers. The mapping lives in one Redactor, i.e.
# one capture, so nothing links across captures.
_JOB_ID = re.compile(r"(?P<pre>(?<![\w.])(?:u\d+[a-z]\d+|\d{4,6})/)(?P<id>-?\d+)(?![\d.])")


# Totals that describe what a file lists. Trimming a fixture (or redaction removing
# blocks) makes them wrong, so they are recounted from what is actually there. On
# an untrimmed dump this changes nothing.
_TOTALS: dict[str, tuple[tuple[re.Pattern[str], re.Pattern[str], int], ...]] = {
    # (header with the total, item line, indent that ends the counted region)
    JOBSCHEDULER_FILENAME: (
        (
            re.compile(r"^(?P<pre>Registered )(?P<n>\d+)(?P<post> jobs:)$"),
            re.compile(r"^  JOB "),
            0,
        ),
    ),
    LAUNCHER_FILENAME: (
        (
            re.compile(r"^(?P<pre>)(?P<n>\d+)(?P<post> activities found:)$"),
            re.compile(r"^  Activity #\d+:$"),
            0,
        ),
    ),
    ALARM_FILENAME: (
        (
            re.compile(r"^(?P<pre>  )(?P<n>\d+)(?P<post> pending alarms: ?)$"),
            re.compile(r"^    \S+ #\d+: Alarm\{"),
            2,
        ),
    ),
}


# Location records: `Location[fused 48.1,2.3 hAcc=13.0 alt=... vel=... bear=...
# satellites=...]`. Altitude, speed and bearing locate a person as well as the
# coordinates do, so a record is replaced whole: `Location[fused REDACTED]`.
def _location_records(text: str) -> list[tuple[int, int, str]]:
    """(start, end, provider) of each `Location[...]` record, brackets balanced."""
    found: list[tuple[int, int, str]] = []
    for m in re.finditer(r"Location\[", text):
        depth, i = 1, m.end()
        while i < len(text) and depth and text[i] != "\n":
            depth += {"[": 1, "]": -1}.get(text[i], 0)
            i += 1
        body = text[m.end() : i - 1] if depth == 0 else text[m.end() : i]
        first = body.split(" ", 1)[0]
        provider = first if re.fullmatch(r"[A-Za-z]+", first) else ""
        found.append((m.start(), i, provider))
    return found


def _placeholder_record(provider: str) -> str:
    return f"Location[{provider} REDACTED]" if provider else "Location[REDACTED]"


def redact_location_records(text: str) -> tuple[str, int]:
    changed = 0
    for start, end, provider in reversed(_location_records(text)):
        new = _placeholder_record(provider)
        if text[start:end] != new:
            text = text[:start] + new + text[end:]
            changed += 1
    return text, changed


def _unredacted_location_records(text: str) -> list[tuple[int, str]]:
    return [
        (text.count("\n", 0, start) + 1, text[start : min(end, start + 40)])
        for start, end, provider in _location_records(text)
        if text[start:end] != _placeholder_record(provider)
    ]


# Geofences can encode home or work, so every entry under `Geofence Manager:` goes;
# only the header and its `service:` status line stay.
def _geofence_lines(lines: list[str]) -> list[int]:
    hits: list[int] = []
    inside: int | None = None
    for i, raw in enumerate(lines):
        line = raw.rstrip("\n")
        indent = len(line) - len(line.lstrip())
        if line.strip() == "Geofence Manager:":
            inside = indent
            continue
        if inside is None or not line.strip():
            continue
        if indent <= inside:
            inside = None
            continue
        if not re.match(r"^\s+service: ", line):
            hits.append(i)
    return hits


def drop_geofences(text: str) -> tuple[str, int]:
    lines = text.splitlines(keepends=True)
    hits = set(_geofence_lines(lines))
    return "".join(line for i, line in enumerate(lines) if i not in hits), len(hits)


_ALARM_STATS_HEADER = re.compile(
    r"^(?P<pre>  \S+:\S+ (?:\+\S+|0) running, )(?P<n>\d+)(?P<post> wakeups:)$"
)
_ALARM_STATS_ENTRY = re.compile(r"^    (?:\+\S+|0) (?P<w>\d+) wakes \d+ alarms, ")


def _resum_alarm_wakeups(lines: list[str]) -> int:
    """An app's `N wakeups:` header is the sum of its tags' wakes (true on full dumps)."""
    changed, in_stats = 0, False
    for i, raw in enumerate(lines):
        line = raw.rstrip("\n")
        if line.strip() == "Alarm Stats:":
            in_stats = True
            continue
        m = _ALARM_STATS_HEADER.match(line)
        if line.strip() and len(line) - len(line.lstrip()) <= 2 and not m:
            in_stats = False
        if not (in_stats and m):
            continue
        total = 0
        for later in lines[i + 1 :]:
            if later.strip() and len(later) - len(later.lstrip()) <= 2:
                break
            if e := _ALARM_STATS_ENTRY.match(later):
                total += int(e["w"])
        if int(m["n"]) != total:
            lines[i] = f"{m['pre']}{total}{m['post']}" + raw[len(raw.rstrip("\n")) :]
            changed += 1
    return changed


def recount_totals(text: str, name: str) -> tuple[str, int]:
    """Rewrite known totals to the number of items listed under them."""
    rules = _TOTALS.get(name)
    if not rules:
        return text, 0
    lines = text.splitlines(keepends=True)
    changed = _resum_alarm_wakeups(lines) if name == ALARM_FILENAME else 0
    for header, item, end_indent in rules:
        for i, raw in enumerate(lines):
            m = header.match(raw.rstrip("\n"))
            if not m:
                continue
            count = 0
            for later in lines[i + 1 :]:
                if later.strip() and len(later) - len(later.lstrip()) <= end_indent:
                    break
                count += bool(item.match(later))
            if int(m["n"]) != count:
                lines[i] = f"{m['pre']}{count}{m['post']}" + raw[len(raw.rstrip("\n")) :]
                changed += 1
    return "".join(lines), changed


def scan(text: str, packages: PackagePolicy | None = None, name: str = "") -> list[Finding]:
    """Identifiers that aren't placeholders, disallowed packages, and unshifted times."""
    findings: list[Finding] = [
        Finding("unshifted_time", v, line) for line, v in unshifted_times(text, name)
    ]
    lines = text.splitlines()
    findings += [
        Finding("network_detail", lines[i].strip()[:40], i + 1) for i in _network_lines(lines)
    ]
    findings += [Finding("location_record", v, n) for n, v in _unredacted_location_records(text)]
    findings += [Finding("geofence", lines[i].strip()[:40], i + 1) for i in _geofence_lines(lines)]
    if packages is not None:
        findings += [Finding("package", pkg, line) for line, pkg in packages.scan(text)]
    return findings + identifiers(text)


def identifiers(text: str) -> list[Finding]:
    """Device and personal identifiers (serials, IMEIs, emails, phone numbers, MAC/IP
    addresses, coordinates, ...) that aren't placeholders. Used on fixtures and on
    redacted reports."""
    findings: list[Finding] = []
    for det, m in _matches(text):
        if not det.scan:
            continue
        for value in _elements(det, m.group(det.group)):
            if _is_personal(det, value):
                line = text.count("\n", 0, m.start(det.group)) + 1
                findings.append(Finding(det.category, value, line))
    return findings


@dataclass
class Redactor:
    """Consistent redaction across many files. Reuse one instance for a whole fixture set."""

    extra: Iterable[str] = ()
    mapping: dict[str, dict[str, str]] = field(default_factory=dict)
    literals: dict[str, tuple[str, str]] = field(default_factory=dict)  # original -> (cat, ph)
    counts: Counter[str] = field(default_factory=Counter)
    packages: PackagePolicy = field(default_factory=PackagePolicy)
    clock: CaptureClock = field(default_factory=CaptureClock)
    job_ids: dict[tuple[str, str], str] = field(default_factory=dict)  # (owner, id) -> n

    def __post_init__(self) -> None:
        for value in self.extra:
            if value.strip():
                self._add_literal("device_id", value.strip())

    def placeholder(self, category: str, value: str) -> str:
        table = self.mapping.setdefault(category, {})
        if value not in table:
            table[value] = PLACEHOLDERS[category](len(table) + 1)
        return table[value]

    def _add_literal(self, category: str, value: str) -> None:
        if value not in self.literals and not is_placeholder(category, value):
            self.literals[value] = (category, self.placeholder(category, value))

    def harvest(self, text: str, name: str = "") -> None:
        """Collect device-unique values (serial, PARTUUID, ...), package lists and the clock."""
        self.packages.harvest(name, text)
        self.clock.harvest(name, text)
        for m in _SEED_LINE.finditer(text):
            key, value = m.group("k"), m.group("v").strip()
            if value.lower() in _SEED_SKIP or len(value) < 6:
                continue
            for category, pattern in SEED_KEYS.items():
                if pattern.fullmatch(key):
                    self._add_literal(category, value)

    def redact(self, text: str, name: str = "") -> str:
        before = self.packages.removed
        text = self.packages.redact(text)
        if self.packages.removed > before:
            self.counts["package"] += self.packages.removed - before
        text, recounted = recount_totals(text, name)
        if recounted:
            self.counts["total_recounted"] += recounted
        text, n_records = redact_location_records(text)
        if n_records:
            self.counts["location_record"] += n_records
        text, n_geo = drop_geofences(text)
        if n_geo:
            self.counts["geofence"] += n_geo
        text, dropped = drop_network_details(text)
        if dropped:
            self.counts["network_detail"] += dropped
        if name == JOBSCHEDULER_FILENAME:
            text = _JOB_ID.sub(self._job_id, text)
        shifted = self.clock.shifted
        text = self.clock.shift(text, name)  # before the detectors: they see shifted times
        if self.clock.shifted > shifted:
            self.counts["time_shift"] += self.clock.shifted - shifted
        if self.literals:
            alternation = "|".join(
                re.escape(v) for v in sorted(self.literals, key=len, reverse=True)
            )
            # Whole tokens only, so a short seed can't match inside a longer number.
            alternation = rf"(?<![A-Za-z0-9])(?:{alternation})(?![A-Za-z0-9])"

            def literal(m: re.Match[str]) -> str:
                category, ph = self.literals[m.group(0)]
                self.counts[category] += 1
                return ph

            text = re.sub(alternation, literal, text)

        for det in DETECTORS:
            text = det.pattern.sub(functools.partial(self._replace, det), text)
        return text

    def _job_id(self, m: re.Match[str]) -> str:
        key = (m["pre"], m["id"])
        if key not in self.job_ids:
            self.job_ids[key] = str(len(self.job_ids) + 1)
            self.counts["job_id"] += 1
        return m["pre"] + self.job_ids[key]

    def _neutral_or_placeholder(self, det: Detector, value: str) -> str:
        if det.fixed is not None:
            new = det.fixed
        elif det.transform is not None:
            new = det.transform(value)
        else:
            return self.placeholder(det.category, value)
        self.mapping.setdefault(det.category, {})[value] = new
        return new

    def _replace(self, det: Detector, m: re.Match[str]) -> str:
        value = m.group(det.group)
        parts = _elements(det, value)
        new_parts = []
        for part in parts:
            if _is_personal(det, part):
                self.counts[det.category] += 1
                new_parts.append(self._neutral_or_placeholder(det, part))
            else:
                new_parts.append(part)
        new_value = det.split.join(new_parts) if det.split else new_parts[0]
        whole = m.group(0)
        start = m.start(det.group) - m.start(0)
        return whole[:start] + new_value + whole[start + len(value) :]


# --- Files ------------------------------------------------------------------


def mask(value: str) -> str:
    """Show enough of a value to locate it without printing it (e.g. in CI logs)."""
    return value[:2] + "*" * max(len(value) - 2, 3)


def iter_files(
    sources: Iterable[Path], committable_only: bool = False
) -> Iterator[tuple[Path, Path]]:
    """Yield (file, path relative to its source root) for files and directory trees.

    ``committable_only``: in a git work tree, only files git tracks or could commit
    (``git ls-files -co --exclude-standard``), so ignored folders such as a local
    ``cases/`` are skipped. Outside a work tree every file is yielded.
    """
    for src in sources:
        if src.is_dir():
            listed = committable(src) if committable_only else None
            files = (
                listed if listed is not None else sorted(p for p in src.rglob("*") if p.is_file())
            )
            for path in files:
                rel = path.relative_to(src)
                # Skip .git, .venv, tool caches and the like when pointed at a whole repo.
                if any(part.startswith(".") or part == "__pycache__" for part in rel.parts[:-1]):
                    continue
                yield path, rel
        else:
            yield src, Path(src.name)


@dataclass
class TreeResult:
    written: list[Path] = field(default_factory=list)
    skipped: list[tuple[Path, str]] = field(default_factory=list)
    remaining: list[tuple[Path, Finding]] = field(default_factory=list)


def redact_tree(sources: Iterable[Path], out: Path, redactor: Redactor) -> TreeResult:
    """Redact every text file under ``sources`` into ``out``, consistently across files.

    Nothing is written unless the redacted output scans clean.
    """
    result = TreeResult()
    texts: list[tuple[Path, str]] = []
    for path, rel in iter_files(sources):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            result.skipped.append((path, "not UTF-8 text"))
            continue
        texts.append((rel, text))
        redactor.harvest(text, rel.name)  # pass 1: seeds and package lists from every file

    redacted = [(rel, redactor.redact(text, rel.name)) for rel, text in texts]  # pass 2
    for rel, text in redacted:
        result.remaining += [(out / rel, f) for f in scan(text, redactor.packages, rel.name)]
    if result.remaining:
        return result
    for rel, text in redacted:
        dest = out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
        result.written.append(dest)
    return result


def scan_tree(
    sources: Iterable[Path],
    allowlist: tuple[AllowedPackage, ...] = DEFAULT_ALLOWLIST,
    third_party: set[str] | None = None,
) -> list[tuple[Path, Finding]]:
    """Scan files for identifiers and for third-party packages not on ``allowlist``.

    With ``third_party`` (your own app list; local only, never in CI), also report
    any mention of those apps anywhere in the files, not just where a package
    name is expected.
    """
    texts: list[tuple[Path, str]] = []
    for path, _ in iter_files(sources, committable_only=True):
        try:
            texts.append((path, path.read_text(encoding="utf-8")))
        except UnicodeDecodeError:
            continue
    packages = policy_for_tree(((p.name, t) for p, t in texts), allowlist)
    findings = [(path, f) for path, text in texts for f in scan(text, packages, path.name)]
    if third_party:
        packages.listed |= third_party
        findings += [
            (path, Finding("my_app", name, line))
            for path, text in texts
            for line, name in packages.known_mentions(_names_file_exempt(path, text))
        ]
    return findings


def _names_file_exempt(path: Path, text: str) -> str:
    """The one exemption from the "your apps" check: the rows of the generated
    Wikidata names file (appopsy/report/app_names.tsv). It lists every app with a
    Play ID on Wikidata, so it necessarily names some of anyone's apps without
    revealing which. Only while the file validates (strict format, at least
    MIN_ROWS rows, the generator's exact query in the header); its header is
    always scanned, and an invalid file is scanned whole (fail closed). Line
    numbers are kept by blanking the exempt rows."""
    if not path.as_posix().endswith(app_names.PATH_IN_REPO) or app_names.validate(text):
        return text
    return "\n".join(line if line.startswith("#") else "" for line in text.splitlines())
