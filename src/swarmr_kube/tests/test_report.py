"""What reaches the caller, and what is suppressed on the way.

Every case here comes from a live run. The team reads cluster state, so it can
observe a fault but cannot validate a correction, and four prompt attempts
failed to stop the model offering one anyway. Suppression therefore lives in the
render path, and these tests are its specification.
"""

from __future__ import annotations

import pytest

from swarmr_kube.report_tool import render_report_args


def test_filed_arguments_render_every_section() -> None:
    text = render_report_args(
        {
            "symptom": "502 via ingress",
            "root_cause": "targetPort 8081 vs 80",
            "evidence": ["Service: targetPort 8081 (network)"],
            "critic_ruling": "confirmed",
            "fix_object": "Service demo/payments",
            "fix_locator": "spec.ports[0].targetPort: 8081",
            "dismissed": ["arch mismatch (platform)"],
        }
    )
    for heading in (
        "SYMPTOM",
        "ROOT CAUSE",
        "EVIDENCE",
        "DISMISSED",
        "CRITIC RULING",
    ):
        assert heading in text


def test_an_unvalidated_replacement_never_reaches_the_report() -> None:
    """A live run put "instead of worker_connections" in the root cause: a
    value invalid in that config context, so acting on it reproduces the
    outage. The sentence goes; the rest of the chain stays."""
    text = render_report_args(
        {
            "root_cause": (
                'ConfigMap demo/checkout-config contains "wroker_connections '
                '1024;" instead of "worker_connections 1024;". nginx exits 1 '
                "and the container enters CrashLoopBackOff."
            ),
            "evidence": ["e"],
        }
    )
    assert "worker_connections 1024" not in text
    assert "CrashLoopBackOff" in text
    assert "One sentence omitted" in text


@pytest.mark.parametrize(
    "phrasing",
    [
        'contains "wroker_connections" instead of "worker_connections".',
        # Verbatim from a live commander dispatch: a naming-only marker set
        # missed this, so the same invalid value could be copied through.
        "the invalid directive 'wroker_connections' (typo for "
        "'worker_connections') kills nginx.",
        "line 3 has wroker_connections, a misspelling of worker_connections.",
        "the directive should read worker_connections.",
    ],
)
def test_every_way_of_naming_the_replacement_is_pruned(phrasing: str) -> None:
    text = render_report_args({"root_cause": phrasing, "evidence": ["e"]})
    assert "worker_connections" not in text.replace("wroker_connections", "")
    assert "One sentence omitted" in text


def test_a_fully_pruned_diagnosis_is_not_an_all_clear() -> None:
    """ "none found" means a healthy cluster; a pruned one must not borrow it."""
    text = render_report_args(
        {"root_cause": "targets 8081 instead of 80.", "evidence": ["e"]}
    )
    assert "none found" not in text
    assert "withheld" in text


def test_two_observed_readings_survive_whole() -> None:
    chain = (
        "Service demo/payments targets 8081; the container listens on 80 "
        "only, so nothing accepts the probe."
    )
    text = render_report_args({"root_cause": chain, "evidence": ["e"]})
    assert chain in text
    assert "omitted" not in text


def test_fix_location_always_carries_its_caveat() -> None:
    """The team points at the fault; it does not certify a fix."""
    text = render_report_args(
        {
            "symptom": "s",
            "root_cause": "r",
            "fix_object": "ConfigMap demo/checkout-config",
            "fix_locator": "key default.conf, line 3: wroker_connections 1024;",
        }
    )
    assert "WHERE TO FIX IT" in text
    assert "Location only" in text


def test_a_prescription_is_dropped_from_the_delivered_report() -> None:
    """Four prompt attempts failed to stop the model prescribing fixes it
    cannot validate — one of which would still have crashed nginx.

    Suppression lives in the render path because the filed report is emitted
    from the call arguments before the tool returns, so nothing the tool body
    does can protect what the caller receives.
    """
    recipe = (
        "Edit ConfigMap demo/checkout-config key default.conf and replace the "
        "misspelled directive wroker_connections with worker_connections; the "
        "Deployment will roll out corrected pods once the ConfigMap is updated."
    )
    text = render_report_args(
        {
            "root_cause": "r",
            "fix_object": "ConfigMap demo/checkout-config",
            "fix_locator": recipe,
        }
    )
    assert "WHERE TO FIX IT" in text
    assert "  ConfigMap demo/checkout-config" in text.splitlines()
    for smuggled in ("replace", "worker_connections", "will roll out", "Edit"):
        assert smuggled not in text


def test_an_observed_coordinate_survives_intact() -> None:
    text = render_report_args(
        {
            "root_cause": "r",
            "fix_object": "ConfigMap demo/checkout-config",
            "fix_locator": "key default.conf, line 3: wroker_connections 1024;",
        }
    )
    assert "line 3: wroker_connections 1024;" in text


def test_no_caveat_when_no_location_is_given() -> None:
    text = render_report_args({"symptom": "s", "root_cause": "none found"})
    assert "WHERE TO FIX IT" not in text


def test_missing_root_cause_reads_as_none_found() -> None:
    """A healthy cluster is a valid outcome and must render as one."""
    assert "none found" in render_report_args({"symptom": "nothing reported"})


def test_a_single_string_evidence_value_is_accepted() -> None:
    text = render_report_args(
        {"symptom": "s", "root_cause": "r", "evidence": "one line only"}
    )
    assert "- one line only" in text
