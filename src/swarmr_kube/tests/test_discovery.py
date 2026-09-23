"""The cluster facts every prompt is built from.

`render_facts` and `render_routing` are not reports for a human: they are the
prompt text four investigators reason against, so a wrong sentence here is a
wrong investigation. Both are pure functions of a profile, so they are pinned
directly from hand-built profiles rather than from a live cluster.
"""

from __future__ import annotations

import pytest

from swarmr_kube.discovery import (
    ClusterProfile,
    render_facts,
    render_routing,
)


def _node(name: str, arch: str, **extra: str) -> dict[str, str]:
    return {
        "name": name,
        "arch": arch,
        "roles": "worker",
        "os": "Ubuntu 24.04",
        "ready": "True",
        "taints": "",
    } | extra


class TestArchitecture:
    def test_a_mixed_cluster_names_both_architectures(self) -> None:
        """On a mixed cluster an arch mismatch is a live hypothesis, so the
        prompt must say which architectures are actually present."""
        text = render_facts(
            ClusterProfile(
                nodes=[_node("n1", "amd64"), _node("n2", "arm64")],
                architectures=["amd64", "arm64"],
            )
        )
        assert "HETEROGENEOUS ARCHITECTURE" in text
        assert "mixes amd64 and arm64" in text
        assert "first-class hypothesis" in text

    def test_a_uniform_cluster_rules_a_subset_failure_out(self) -> None:
        """Pods failing on some nodes but not others cannot be an arch mismatch
        when every node is the same architecture: say so, or it gets blamed."""
        text = render_facts(
            ClusterProfile(nodes=[_node("n1", "arm64")], architectures=["arm64"])
        )
        assert "All nodes are arm64" in text
        assert "fail on every node equally, never on a subset" in text
        assert "HETEROGENEOUS" not in text


class TestAbsentSystems:
    def test_missing_observability_is_named_as_uncitable(self) -> None:
        """An investigator citing Prometheus on a cluster without it is
        inventing evidence, which reads exactly like a real finding."""
        text = render_facts(
            ClusterProfile(
                nodes=[_node("n1", "amd64")],
                architectures=["amd64"],
                observability=["metrics-server"],
                absent=["Loki", "Prometheus"],
            )
        )
        assert "NOT present, so no evidence can possibly come from it" in text
        assert "Loki, Prometheus" in text
        assert "Never cite these systems" in text

    def test_absent_ingress_is_not_assumed_to_exist(self) -> None:
        text = render_facts(
            ClusterProfile(nodes=[_node("n1", "amd64")], architectures=["amd64"])
        )
        assert "none detected" in text
        assert "do not assume one exists" in text


class TestBaselineNoise:
    def test_a_surviving_cohort_is_declared_baseline(self) -> None:
        """A cohort sharing one restart age is a host event; the critic needs it
        named so "the node restarted" can be rejected as an explanation."""
        text = render_facts(
            ClusterProfile(
                nodes=[_node("n1", "amd64")],
                architectures=["amd64"],
                baseline_restarts=["9 containers last restarted about 30h ago"],
            )
        )
        assert "<known-baseline-noise>" in text
        assert "9 containers last restarted about 30h ago" in text
        assert "NON-explanation" in text

    def test_a_cohort_below_the_threshold_is_never_mentioned(self) -> None:
        """Restarts that did not clear the threshold leave the list empty, and an
        empty list must not produce a baseline block excusing real restarts."""
        text = render_facts(
            ClusterProfile(
                nodes=[_node("n1", "amd64")],
                architectures=["amd64"],
                baseline_restarts=[],
            )
        )
        assert "known-baseline-noise" not in text
        assert "NON-explanation" not in text


class TestRoutingMechanics:
    @pytest.mark.parametrize(
        ("controller", "missing", "refused"),
        [("Traefik", "503", "502"), ("Istio", "503", "503")],
    )
    def test_status_codes_follow_the_installed_controller(
        self, controller: str, missing: str, refused: str
    ) -> None:
        """Istio answers 503 for a refused connection where Traefik answers 502;
        stating one controller's mechanics for another mislabels the fault."""
        text = render_routing(
            ClusterProfile(ingress=[(controller, "ingress")]),
        )
        assert f"This cluster's ingress is {controller}" in text
        assert f"has no backend to dial -> HTTP {missing}" in text
        assert f"the connection is refused -> HTTP {refused}" in text
        assert f"A failing readinessProbe yields {missing}, never {refused}" in text

    def test_without_a_controller_no_status_code_is_invented(self) -> None:
        """Nothing terminates HTTP, so a 502/503 story would be fabricated."""
        text = render_routing(ClusterProfile())
        assert "No ingress controller was detected" in text
        assert "do not invent HTTP status codes" in text
        assert "502" not in text
        assert "503" not in text
