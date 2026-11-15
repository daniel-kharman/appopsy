"""appopsy: an autopsy of what your Android apps have been doing."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("appopsy")
except PackageNotFoundError:  # pragma: no cover - running from a source tree without install
    __version__ = "0+unknown"
