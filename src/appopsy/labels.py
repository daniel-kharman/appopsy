"""Plain-English names shared by rule summaries and reports.

Prose uses these; op constants (FINE_LOCATION) and UID-state codes (bg, cch)
appear only in report tables and in the raw evidence.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

# For tables: a short name, shown with the op constant next to it.
OP_NAMES = {
    "FINE_LOCATION": "precise location",
    "COARSE_LOCATION": "approximate location",
    "CAMERA": "camera",
    "RECORD_AUDIO": "microphone",
    "READ_CONTACTS": "contacts",
    "READ_CALL_LOG": "call log",
    "READ_SMS": "text messages",
    "READ_MEDIA_IMAGES": "photos",
    "READ_MEDIA_VIDEO": "videos",
    "READ_MEDIA_VISUAL_USER_SELECTED": "photos and videos you picked",
    "BODY_SENSORS": "body sensors",
    "RUN_ANY_IN_BACKGROUND": "running in the background",
}
# For sentences ("used the camera", "can read your contacts").
OP_PROSE = {
    "FINE_LOCATION": "precise location",
    "COARSE_LOCATION": "approximate location",
    "CAMERA": "the camera",
    "RECORD_AUDIO": "the microphone",
    "READ_CONTACTS": "your contacts",
    "READ_CALL_LOG": "your call log",
    "READ_SMS": "your text messages",
    "READ_MEDIA_IMAGES": "your photos",
    "READ_MEDIA_VIDEO": "your videos",
    "READ_MEDIA_VISUAL_USER_SELECTED": "photos and videos you picked",
    "BODY_SENSORS": "body sensors",
    "RUN_ANY_IN_BACKGROUND": "running in the background",
}
# appops UID states (CLAUDE.md, "Parsing notes"); tables only.
STATE_NAMES = {
    "top": "open on screen",
    "fg": "in the foreground",
    "fgsvc": "foreground service",
    "bg": "in the background",
    "cch": "cached in the background",
    "pers": "persistent",
}
# Job constraints. TIMING_DELAY ("wait at least this long") is left out of reports:
# every job has one and it constrains nothing.
REQUIREMENT_NAMES = {
    "CHARGING": "charging",
    "IDLE": "phone idle",
    "BATTERY_NOT_LOW": "battery not low",
    "STORAGE_NOT_LOW": "storage not low",
    "DEADLINE": "a deadline",
    "ANY_NETWORK": "any network",
    "UNMETERED_NETWORK": "unmetered network (e.g. Wi-Fi)",
    "CONNECTIVITY": "a network (type not recorded)",
    "CONTENT_TRIGGER": "a content change",
}
UNREPORTED_REQUIREMENTS = frozenset({"TIMING_DELAY"})


def op_label(op: str) -> str:
    name = OP_NAMES.get(op)
    return f"{name} ({op})" if name else op


def op_prose(op: str) -> str:
    return OP_PROSE.get(op, op.replace("_", " ").lower())


def state_label(state: str) -> str:
    return STATE_NAMES.get(state, state)


def requirement_label(requirement: str) -> str:
    return REQUIREMENT_NAMES.get(requirement, requirement.replace("_", " ").lower())


def short_class(name: str) -> str:
    """`com.facebook.falco.jobscheduler.FFJobService` -> `FFJobService`;
    `Outer$Inner` -> `Inner`."""
    return name.rsplit(".", 1)[-1].rsplit("$", 1)[-1] or name


def join(items: Sequence[str]) -> str:
    """ "a", "a and b", "a, b and c"."""
    items = list(items)
    if len(items) <= 1:
        return "".join(items)
    return f"{', '.join(items[:-1])} and {items[-1]}"


def sample(items: Sequence[str], limit: int = 3) -> str:
    """At most ``limit`` items, then a count: "a, b, c and 11 more"."""
    items = list(items)
    if len(items) <= limit:
        return join(items)
    return f"{', '.join(items[:limit])} and {len(items) - limit} more"


def access_phrase(ops: Iterable[str]) -> str:
    """Kinds of access in a sentence, one "your" for personal data:
    "your location, contacts, photos and videos, plus the camera"."""
    ops = set(ops)
    personal: list[str] = []
    location = ops & {"FINE_LOCATION", "COARSE_LOCATION"}
    if location:
        personal.append("location" if len(location) == 2 else OP_NAMES[next(iter(location))])
    personal += [OP_NAMES[op] for op in ("READ_CONTACTS", "READ_CALL_LOG", "READ_SMS") if op in ops]
    images, video = "READ_MEDIA_IMAGES" in ops, "READ_MEDIA_VIDEO" in ops
    # Separate items, so a list reads "contacts, photos and videos".
    personal += [name for flag, name in ((images, "photos"), (video, "videos")) if flag]
    if "BODY_SENSORS" in ops:
        personal.append("body-sensor data")
    other: list[str] = []
    if "READ_MEDIA_VISUAL_USER_SELECTED" in ops and not (images or video):
        other.append("the photos and videos you picked")
    other += [OP_PROSE[op] for op in ("CAMERA", "RECORD_AUDIO") if op in ops]
    if "RUN_ANY_IN_BACKGROUND" in ops:
        other.append("running in the background")
    if personal and other:
        return f"your {join(personal)}, plus {join(other)}"
    return f"your {join(personal)}" if personal else join(other)


@dataclass(frozen=True)
class AccessCategory:
    """A kind of sensitive access, as a person thinks of it, and the ops behind it."""

    key: str
    name: str  # for tables: "Location"
    ops: tuple[str, ...]
    full: frozenset[str]  # ops that mean full access; the others are partial
    full_detail: str = ""  # e.g. "precise"
    partial_detail: str = ""  # e.g. "approximate only"


ACCESS_CATEGORIES = (
    AccessCategory("location", "Location", ("FINE_LOCATION", "COARSE_LOCATION"),
                   frozenset({"FINE_LOCATION"}), "precise", "approximate only"),
    AccessCategory("camera", "Camera", ("CAMERA",), frozenset({"CAMERA"})),
    AccessCategory("microphone", "Microphone", ("RECORD_AUDIO",), frozenset({"RECORD_AUDIO"})),
    AccessCategory("contacts", "Contacts", ("READ_CONTACTS",), frozenset({"READ_CONTACTS"})),
    AccessCategory("call_log", "Call log", ("READ_CALL_LOG",), frozenset({"READ_CALL_LOG"})),
    AccessCategory("sms", "Text messages", ("READ_SMS",), frozenset({"READ_SMS"})),
    AccessCategory("photos_videos", "Photos and videos",
                   ("READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_VISUAL_USER_SELECTED"),
                   frozenset({"READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO"}),
                   "whole library", "selected photos only"),
    AccessCategory("body_sensors", "Body sensors", ("BODY_SENSORS",), frozenset({"BODY_SENSORS"})),
    AccessCategory("background", "Running in the background", ("RUN_ANY_IN_BACKGROUND",),
                   frozenset({"RUN_ANY_IN_BACKGROUND"})),
)  # fmt: skip
CATEGORY = {c.key: c for c in ACCESS_CATEGORIES}
# Kept but not counted or suggested as a step: the privacy-friendly choice.
FRIENDLY = frozenset({("photos_videos", "partial")})

_CATEGORY_PROSE = {
    ("location", "full"): "precise location",
    ("location", "partial"): "approximate location",
    ("contacts", "full"): "contacts",
    ("call_log", "full"): "call log",
    ("sms", "full"): "text messages",
    ("body_sensors", "full"): "body-sensor data",
}
_CATEGORY_OTHER = {
    "camera": "the camera",
    "microphone": "the microphone",
    "background": "running in the background",
}


def category_phrase(pairs: Iterable[tuple[str, str]]) -> str:
    """(key, scope) pairs in a sentence: "your precise location, contacts and photos and
    videos, plus the camera"."""
    categories = list(pairs)
    personal, other = [], []
    for key, scope in categories:
        if (key, scope) == ("photos_videos", "full"):
            continue  # added last, as two items: "..., contacts, photos and videos"
        if (key, scope) in _CATEGORY_PROSE:
            personal.append(_CATEGORY_PROSE[key, scope])
        elif key in _CATEGORY_OTHER:
            other.append(_CATEGORY_OTHER[key])
    if ("photos_videos", "full") in categories:
        personal += ["photos", "videos"]
    if personal and other:
        return f"your {join(personal)}, plus {join(other)}"
    return f"your {join(personal)}" if personal else join(other)


# Job names that many apps share because they come from one library, named from
# the class's package where the dump shows it (`ScheduledTaskService` is
# com.google.android.libraries.notifications...; `SyncJobService` is
# com.android.server.content). TikTokWorker comes from a Google app framework of
# that name, not from the TikTok app.
JOB_LIBRARIES = {
    "GnpWorker": "Google Notifications Platform",
    "ScheduledTaskService": "Google notifications library",
    "ChimeScheduledTaskWorker": "Google notifications library",
    "TikTokWorker": "Google's “TikTok” app framework (not the TikTok app)",
    "SyncJobService": "Android account sync",
    "SystemJobService": "WorkManager (worker name not recorded)",
}


def library_label(job: str) -> str:
    """The library a shared job name comes from, or a plain description."""
    return JOB_LIBRARIES.get(job, "a library several apps share")
