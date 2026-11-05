from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from appopsy.parsers.jobscheduler import JobSchedulerSnapshot, parse_jobscheduler

FIXTURE = (
    Path(__file__).parent / "fixtures" / "17-google" / "capture-2" / "dumpsys-jobscheduler.txt"
)


@pytest.fixture(scope="module")
def snap() -> JobSchedulerSnapshot:
    snapshot, warnings = parse_jobscheduler(FIXTURE.read_text())
    assert warnings == []
    return snapshot


def test_registered_jobs(snap: JobSchedulerSnapshot) -> None:
    assert len(snap.jobs) == 28  # matches the (recounted) "Registered 28 jobs:"
    owners = {j.package for j in snap.jobs}
    assert owners == {
        "android", "com.facebook.katana", "com.facebook.orca", "com.google.android.apps.maps",
        "com.google.android.as", "com.google.android.dialer",
    }  # fmt: skip


def test_facebook_workmanager_jobs_and_worker_names(snap: JobSchedulerSnapshot) -> None:
    fb = snap.for_package("com.facebook.katana")
    assert len(fb) == 17
    wm = [j for j in fb if j.is_workmanager]
    assert len(wm) == 11
    workers = {j.worker for j in wm}
    assert {
        "IdentityHashWorker", "StoryTrayPredictionPrefetchWorker", "MediaCountUploadWorker",
        "NewsFeedCacheInvalidationWorker",
    } <= workers  # fmt: skip
    story = next(j for j in fb if j.worker == "StoryTrayPredictionPrefetchWorker")
    assert story.namespace == "androidx.work.systemjobscheduler"
    assert (story.uid, story.app_id, story.user_id, story.label) == (10426, 10426, 0, "u0a426")
    assert story.job_id == "20"  # capture-scoped placeholder
    assert story.service == "androidx.work.impl.background.systemjob.SystemJobService"
    assert story.required == ["TIMING_DELAY", "CONNECTIVITY", "FLEXIBILITY"]
    assert story.requires_charging is False and story.requires_device_idle is False
    assert story.priority == 300
    assert story.minimum_latency == timedelta(minutes=29, seconds=59, milliseconds=925)


def test_plain_jobs_have_a_service_but_no_worker(snap: JobSchedulerSnapshot) -> None:
    media = next(j for j in snap.for_package("com.facebook.katana") if j.job_id == "27")
    assert media.namespace is None and not media.is_workmanager
    assert media.worker is None
    assert media.service == "com.facebook.media.local.UpdateLocalMediaStoreJobService"


def test_unconstrained_jobs(snap: JobSchedulerSnapshot) -> None:
    """Unconstrained = no charging, no device-idle and no unmetered-network
    requirement ("any network" doesn't count). capture-2 predates keeping the
    network class, so jobs that need a network can't be decided: None."""
    fb = snap.for_package("com.facebook.katana")
    by_outcome: dict[bool | None, list[str]] = {True: [], False: [], None: []}
    for j in fb:
        by_outcome[j.is_unconstrained].append(j.job_id)
    assert sorted(by_outcome[True], key=int) == ["16", "27"]  # no network constraint at all
    assert sorted(by_outcome[False], key=int) == ["12", "19", "24"]  # charging or idle
    assert len(by_outcome[None]) == 12  # need a network; capture-2 doesn't say which kind
    notif = next(j for j in fb if j.job_id == "16")
    assert notif.worker == "NotificationsPermissionPeriodicReporter$NotificationsPermissionWorker"
    assert notif.requirements == ["TIMING_DELAY"]


def test_network_class_decides_unconstrained() -> None:
    base = (
        "Registered 2 jobs:\n"
        "  JOB #u0a426/1: a1 com.facebook.katana/com.facebook.A\n"
        "    Source: uid=u0a426 user=0 pkg=com.facebook.katana\n"
        "    JobInfo:\n"
        "      Requires: charging=false batteryNotLow=false deviceIdle=false\n"
        "      Network type: {net}\n"
        "    Required constraints: TIMING_DELAY CONNECTIVITY [0x1]\n"
    )
    any_net = parse_jobscheduler(base.format(net="any"))[0].jobs[0]
    assert (any_net.network, any_net.is_unconstrained) == ("any", True)
    assert any_net.requirements == ["TIMING_DELAY", "ANY_NETWORK"]
    unmetered = parse_jobscheduler(base.format(net="unmetered"))[0].jobs[0]
    assert (unmetered.network, unmetered.is_unconstrained) == ("unmetered", False)


def test_periodic_and_last_run(snap: JobSchedulerSnapshot) -> None:
    periodic = [j for j in snap.jobs if j.periodic_interval is not None]
    assert len(periodic) == 3
    assert {j.periodic_interval for j in periodic} <= {timedelta(days=1), timedelta(hours=1)}
    ran = [j for j in snap.jobs if j.last_successful_run is not None]
    assert ran and all(j.last_successful_run.year == 2029 for j in ran)  # type: ignore[union-attr]


def test_recently_completed(snap: JobSchedulerSnapshot) -> None:
    assert len(snap.completed) == 5
    first = snap.completed[0]
    assert first.ago == timedelta(minutes=4, seconds=23, milliseconds=987)
    assert (first.package, first.worker, first.label) == (
        "com.google.android.apps.maps", "GmmWorkerWrapper", "u0a231",
    )  # fmt: skip


def test_completed_job_without_a_namespace() -> None:
    """Jobs scheduled outside a namespace print no `{...}` (seen on a full dump)."""
    text = (
        "Registered 0 jobs:\n"
        "Recently completed jobs:\n"
        "  -1m56s268ms\n"
        "      157a63f #u0a501/1 com.example.app/com.example.app.TaskService\n"
        "      u0a501 tag=*job*r/com.example.app/com.example.app.TaskService\n"
        "      Source: uid=u0a501 user=0 pkg=com.example.app\n"
    )
    snap, warnings = parse_jobscheduler(text)
    assert warnings == []
    (done,) = snap.completed
    assert (done.label, done.job_id, done.package, done.worker) == (
        "u0a501", "1", "com.example.app", None,
    )  # fmt: skip
    assert done.ago == timedelta(minutes=1, seconds=56, milliseconds=268)


def test_unknown_lines_become_warnings() -> None:
    text = (
        "Registered 1 jobs:\n"
        "  JOB #u0a426/1: abc com.facebook.katana/com.facebook.X\n"
        "    Source: uid=u0a426 user=0 pkg=com.facebook.katana\n"
        "    Required constraints: CHARGING [0x1]\n"
        "    Minimum latency: soon\n"
        "  JOB something unexpected\n"
    )
    snap, warnings = parse_jobscheduler(text)
    assert len(snap.jobs) == 1 and snap.jobs[0].required == ["CHARGING"]
    assert sorted(w.message for w in warnings) == [
        "unrecognised duration",
        "unrecognised job header",
    ]
    assert parse_jobscheduler("Settings:\n")[1][0].message == "no Registered jobs section"
