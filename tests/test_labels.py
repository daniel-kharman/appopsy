from __future__ import annotations

from appopsy.labels import access_phrase, join, sample, short_class


def test_join_and_sample() -> None:
    assert [join([]), join(["a"]), join(["a", "b"]), join(["a", "b", "c"])] == [
        "", "a", "a and b", "a, b and c",
    ]  # fmt: skip
    assert sample(["a", "b", "c"]) == "a, b and c"
    assert sample(list("abcdef")) == "a, b, c and 3 more"


def test_short_class() -> None:
    assert short_class("com.facebook.falco.jobscheduler.FFJobService") == "FFJobService"
    assert short_class("Reporter$NotificationsPermissionWorker") == "NotificationsPermissionWorker"
    assert short_class("IdentityHashWorker") == "IdentityHashWorker"


def test_access_phrase() -> None:
    assert access_phrase(["FINE_LOCATION", "COARSE_LOCATION"]) == "your location"
    assert access_phrase(["COARSE_LOCATION"]) == "your approximate location"
    assert access_phrase(
        ["FINE_LOCATION", "COARSE_LOCATION", "READ_CONTACTS", "READ_MEDIA_IMAGES",
         "READ_MEDIA_VIDEO", "READ_MEDIA_VISUAL_USER_SELECTED", "RUN_ANY_IN_BACKGROUND"]
    ) == "your location, contacts, photos and videos, plus running in the background"  # fmt: skip
    assert access_phrase(["CAMERA", "RECORD_AUDIO"]) == "the camera and the microphone"
    assert access_phrase(["READ_MEDIA_VISUAL_USER_SELECTED"]) == "the photos and videos you picked"
