"""Turning Kubernetes objects into rows a subagent can afford to read.

Raw objects are 4-10 KB each, so a list of them overruns the byte cap and
truncates mid-object, hiding the very field being looked for. These tests pin
the fields that decide a diagnosis.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from swarmr_kube.projection import (
    age,
    clean_log,
    container_state,
    digest,
)


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (0, "0s"),
        (119, "119s"),
        (120, "2m"),
        (7199, "119m"),
        (7200, "2h"),
        (172_799, "47h"),
        (172_800, "2d"),
    ],
)
def test_age_switches_unit_at_each_threshold(seconds: int, expected: str) -> None:
    """A summary carries ages, not timestamps, so the unit boundaries decide
    whether "2m" or "120s" is shown — and whether an hours-old restart reads as
    inside the reported symptom window."""
    assert age(datetime.now(UTC) - timedelta(seconds=seconds)) == expected


def test_age_accepts_the_api_servers_iso_timestamp() -> None:
    """Kubernetes hands back "…Z", which fromisoformat rejected before 3.11."""
    stamp = (datetime.now(UTC) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert age(stamp) == "5m"


def test_a_missing_timestamp_is_not_an_age_of_zero() -> None:
    assert age(None) == "?"


def test_pod_row_carries_the_deciding_fields() -> None:
    row = digest(
        "Pod",
        {
            "metadata": {"name": "p1", "namespace": "demo"},
            "spec": {
                "nodeName": "node1",
                "containers": [{"name": "web", "image": "nginx:1.29"}],
                "nodeSelector": {"kubernetes.io/arch": "arm64"},
            },
            "status": {
                "phase": "Pending",
                "containerStatuses": [
                    {
                        "name": "web",
                        "ready": False,
                        "restartCount": 3,
                        "image": "nginx:1.29",
                        "state": {"waiting": {"reason": "ImagePullBackOff"}},
                    }
                ],
            },
        },
    )
    assert row["ready"] == "0/1"
    assert row["restarts"] == 3
    assert row["containers"]["web"]["state"] == "Waiting/ImagePullBackOff"
    assert row["nodeSelector"] == {"kubernetes.io/arch": "arm64"}


def test_unschedulable_message_is_surfaced() -> None:
    """ "unbound immediate PersistentVolumeClaims" is a storage symptom, not capacity."""
    row = digest(
        "Pod",
        {
            "metadata": {"name": "p1"},
            "spec": {"containers": []},
            "status": {
                "conditions": [
                    {
                        "type": "PodScheduled",
                        "status": "False",
                        "message": "unbound immediate PersistentVolumeClaims",
                    }
                ]
            },
        },
    )
    assert "PersistentVolumeClaims" in row["notScheduled"]


def test_service_row_keeps_target_port_and_drops_empty_fields() -> None:
    """targetPort decides the 502 case; protocol=None is noise in every row."""
    row = digest(
        "Service",
        {
            "metadata": {"name": "payments"},
            "spec": {"ports": [{"port": 80, "targetPort": 8081}]},
        },
    )
    assert row["ports"] == [{"port": 80, "targetPort": 8081}]


def test_endpointslice_row_exposes_readiness() -> None:
    """Ready endpoints on a dead port is 502; no ready endpoints is 503."""
    row = digest(
        "EndpointSlice",
        {
            "metadata": {"name": "payments-zrm82"},
            "ports": [{"port": 8081}],
            "endpoints": [
                {
                    "addresses": ["10.42.2.9"],
                    "conditions": {"ready": True, "serving": True},
                    "nodeName": "node1",
                }
            ],
        },
    )
    assert row["ports"] == [8081]
    assert row["endpoints"][0]["ready"] is True


def test_container_state_collapses_to_one_token() -> None:
    """An empty running dict once rendered as "?" instead of Running."""
    assert container_state({"running": {}}) == "Running"
    assert container_state({"waiting": {"reason": "CrashLoopBackOff"}}) == (
        "Waiting/CrashLoopBackOff"
    )
    assert container_state({"terminated": {"reason": "Error", "exitCode": 1}}) == (
        "Terminated/Error(exit=1)"
    )
    assert container_state(None) == "?"


def test_bytes_repr_and_ansi_are_removed_from_logs() -> None:
    """The client returns the repr of bytes; escapes cost more than the words."""
    raw = "b'2026-01-01T00:00:00Z \\x1b[32mINF\\x1b[0m started\\n'"
    cleaned = clean_log(raw)
    assert "\\x1b" not in cleaned and "b'" not in cleaned
    assert "INF started" in cleaned


def test_repeated_log_lines_collapse() -> None:
    """A probe hitting the same endpoint sixty times says nothing after the first."""
    raw = "\n".join(f"2026-01-01T00:00:0{i}Z GET / 200" for i in range(5))
    cleaned = clean_log(raw)
    assert "repeated 4x" in cleaned
    assert cleaned.count("GET / 200") == 1
