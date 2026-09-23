"""Kubernetes incident response team.

An incident commander delegating to four read-only domain investigators
(workload, network, storage, platform) and a critic that must independently
disprove the resulting hypothesis before it is reported.

The team declares itself here. Deleting this package and its tests removes it
completely: discovery is by entry point, so nothing else in the tree refers to
it, and uninstalling the distribution unregisters it.

Importing this module must stay cheap. It is what `teams --list` and the MCP
server read to publish the team, so anything that pulls in the agent framework,
the model SDK or the Kubernetes client is declared with `lazy` and loaded on
first use. Only the fields `core` may call before a run — the digest and the
error test, both of which are plain string handling — are imported directly.
"""

from __future__ import annotations

from swarmr.core.team import Lazy, Member, Team

from swarmr_kube.digest import digest_result, is_tool_error
from swarmr_kube.prompts import SWEEP_REQUEST

__all__ = ["TEAM"]

_MODULE = "swarmr_kube"

TEAM = Team(
    name="k8s_incident",
    summary="Diagnose a Kubernetes incident and prove the root cause.",
    description=(
        "Investigate a live Kubernetes incident and return a proven root cause. "
        "An incident commander delegates in parallel to four read-only "
        "investigators (workload, network, storage, platform), then a critic "
        "independently tries to disprove the hypothesis before it is reported. "
        "Use for HTTP 502/503 through an ingress, pods that crash-loop or will "
        "not start, ImagePullBackOff, 'exec format error' or other architecture "
        "mismatches, pods stuck in Pending or ContainerCreating, unbound PVCs, "
        "empty Service endpoints, DNS failures, and capacity or scheduling "
        "problems. Also use it to ask whether a cluster is healthy at all: it "
        "will report 'no incident found' rather than invent a fault. Read-only "
        "and diagnostic: it proves the cause and points at the object to fix, but "
        "never changes the cluster and never claims a fix is validated."
    ),
    build=Lazy(f"{_MODULE}.agent:build"),
    profile=Lazy(f"{_MODULE}.agent:profile_target"),
    default_request=SWEEP_REQUEST,
    report_tool="file_incident_report",
    orchestrator="commander",
    audit_agents=("critic",),
    digest=digest_result,
    is_error=is_tool_error,
    render_report=Lazy(f"{_MODULE}.report_tool:render_report_args"),
    members=(
        Member("commander", "orchestrates; holds no cluster tools of its own"),
        Member("workload", "pods, containers, exit codes, probes, logs"),
        Member("network", "Service, EndpointSlice, ingress routes, DNS"),
        Member("storage", "PVC/PV binding, CSI provisioning and mounts"),
        Member("platform", "nodes, scheduling, capacity, image architecture"),
        Member("critic", "independently tries to disprove the hypothesis"),
    ),
    prompt_hint=(
        'requests to http://checkout.demo.local return HTTP 503, namespace "demo"'
    ),
)
