"""One-line summaries of this team's tool payloads.

Domain knowledge, which is why it lives with the team: `core` can only report
shape. These cases pin the ordering trap — an events payload also carries
"count", so the generic list branch must be tested last.
"""

from __future__ import annotations

import json

from swarmr_kube.digest import digest_result


def test_object_list_names_the_first_few() -> None:
    payload = json.dumps(
        {"kind": "Pod", "count": 2, "items": [{"name": "a"}, {"name": "b"}]}
    )
    assert digest_result(payload) == "Pod x2 [a, b]"


def test_long_lists_are_marked_as_truncated() -> None:
    payload = json.dumps(
        {"kind": "Pod", "count": 9, "items": [{"name": f"p{i}"} for i in range(9)]}
    )
    assert digest_result(payload) == "Pod x9 [p0, p1, p2 +…]"


def test_events_are_counted_before_the_generic_list_branch() -> None:
    payload = json.dumps(
        {
            "count": 2,
            "events": [
                {"type": "Warning", "reason": "Unhealthy"},
                {"type": "Normal", "reason": "Pulled"},
            ],
        }
    )
    assert digest_result(payload) == "2 events, 1 warning [Unhealthy]"


def test_registry_platforms_are_listed() -> None:
    payload = json.dumps({"platforms": ["linux/amd64", "linux/arm64"]})
    assert digest_result(payload) == "platforms linux/amd64, linux/arm64"


def test_named_object_reads_as_kind_slash_name() -> None:
    payload = json.dumps({"kind": "Node", "name": "node1"})
    assert digest_result(payload) == "Node/node1"


def test_tool_error_is_shown_verbatim() -> None:
    assert digest_result("tool error: unknown kind 'x'").startswith("tool error")


def test_truncated_json_is_reported_as_such() -> None:
    assert "truncated json" in digest_result('{"kind": "Pod", "items": [{"na')


def test_log_output_summarises_the_newest_line() -> None:
    logs = "2026-01-01T00:00:00Z first\n2026-01-01T00:00:01Z newest line here"
    summary = digest_result(logs)
    assert summary.startswith("2 log lines")
    assert "newest line here" in summary
