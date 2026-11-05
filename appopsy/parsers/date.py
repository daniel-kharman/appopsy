"""Parser for the device clock (`date +%s` and `date +%Y-%m-%dT%H:%M:%S%z`)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import BaseModel

from appopsy.parsers.base import ParseWarning

SOURCE = "date"
# Raw file names used by the date collector. The redactor reads the capture
# clock from these to shift every timestamp in a capture (see redact_time).
EPOCH_FILENAME = "date-epoch.txt"
LOCAL_FILENAME = "date-local.txt"
LOCAL_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
# The two commands run a fraction of a second apart.
MAX_DISAGREEMENT = timedelta(seconds=5)


class DeviceClock(BaseModel):
    utc: datetime
    utc_offset: timedelta | None = None
    local: datetime | None = None


def parse_device_clock(
    epoch_text: str, local_text: str
) -> tuple[DeviceClock | None, list[ParseWarning]]:
    warnings: list[ParseWarning] = []
    epoch = epoch_text.strip()
    if not epoch.isdigit():
        warnings.append(ParseWarning(source=SOURCE, text=epoch, message="epoch is not a number"))
        return None, warnings
    utc = datetime.fromtimestamp(int(epoch), UTC)

    local_str = local_text.strip()
    if not local_str:
        warnings.append(ParseWarning(source=SOURCE, message="no local time; UTC offset unknown"))
        return DeviceClock(utc=utc), warnings
    try:
        local = datetime.strptime(local_str, LOCAL_FORMAT)
    except ValueError:
        warnings.append(
            ParseWarning(source=SOURCE, text=local_str, message="unrecognised local time format")
        )
        return DeviceClock(utc=utc), warnings

    if abs(local - utc) > MAX_DISAGREEMENT:
        warnings.append(
            ParseWarning(
                source=SOURCE,
                text=local_str,
                message=f"epoch and local time disagree by {abs(local - utc)}",
            )
        )
    return DeviceClock(utc=utc, utc_offset=local.utcoffset(), local=local), warnings
