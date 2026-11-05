"""Parsers: raw command output -> pydantic models.

Parsers never raise on unexpected input. Lines or sections they can't
understand are reported as :class:`ParseWarning` and skipped.
"""

from appopsy.parsers.base import ParseWarning

__all__ = ["ParseWarning"]
