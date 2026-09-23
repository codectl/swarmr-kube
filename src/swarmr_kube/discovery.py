"""Runtime profiling of the target cluster.

Nothing about the target cluster is baked into the prompts. This module asks
the API server what it is looking at and renders the facts investigators need:
node architectures, which ingress controller is in play, which storage
provisioners exist, which observability systems are absent, and what the
cluster's restart baseline is so the critic can reject it by name.

Every call here is a read. It runs once at startup, before the first token.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime

from kubernetes import client

from swarmr_kube.client import kube_clients

__all__ = ["ClusterProfile", "profile_cluster", "render_facts", "render_routing"]

# Workload-name fragments that identify a component. Matching is substring
# based because vendors prefix and suffix freely (traefik, rke2-ingress-nginx).
_INGRESS_SIGNS = {
    "traefik": "Traefik",
    "ingress-nginx": "ingress-nginx",
    "nginx-ingress": "ingress-nginx",
    "haproxy-ingress": "HAProxy",
    "istio-ingressgateway": "Istio",
    "contour": "Contour",
    "kong": "Kong",
    "cilium-ingress": "Cilium",
}
_OBSERVABILITY_SIGNS = {
    "prometheus": "Prometheus",
    "victoria-metrics": "VictoriaMetrics",
    "loki": "Loki",
    "grafana": "Grafana",
    "tempo": "Tempo",
    "jaeger": "Jaeger",
    "opentelemetry": "OpenTelemetry",
    "datadog": "Datadog",
    "metrics-server": "metrics-server",
}
_GITOPS_SIGNS = {
    "argocd": "Argo CD",
    "argo-cd": "Argo CD",
    "flux": "Flux",
    "helm-controller": "Flux helm-controller",
}
_CSI_HINTS = {
    "csi-nfs": ("csi-nfs-controller", "csi-nfs-node"),
    "local-path": ("local-path-provisioner",),
}

# How each controller answers when a backend is missing vs unreachable.
_ROUTING_SEMANTICS = {
    "Traefik": ("503", "502"),
    "ingress-nginx": ("503", "502"),
    "HAProxy": ("503", "502"),
    "Contour": ("503", "502"),
    "Istio": ("503", "503"),
    "Kong": ("503", "502"),
}


@dataclass(slots=True)
class ClusterProfile:
    version: str = "unknown"
    nodes: list[dict[str, str]] = field(default_factory=list)
    architectures: list[str] = field(default_factory=list)
    ingress: list[tuple[str, str]] = field(default_factory=list)
    provisioners: list[str] = field(default_factory=list)
    default_storage_class: str | None = None
    csi_workloads: list[str] = field(default_factory=list)
    observability: list[str] = field(default_factory=list)
    gitops: list[str] = field(default_factory=list)
    absent: list[str] = field(default_factory=list)
    workload_namespaces: list[str] = field(default_factory=list)
    baseline_restarts: list[str] = field(default_factory=list)

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def heterogeneous(self) -> bool:
        return len(self.architectures) > 1

    @property
    def controller(self) -> str | None:
        return self.ingress[0][0] if self.ingress else None


def _bucket(name: str, signs: dict[str, str]) -> str | None:
    lowered = name.lower()
    for fragment, label in signs.items():
        if fragment in lowered:
            return label
    return None


def _hours_since(ts: datetime | None) -> float | None:
    if not ts:
        return None
    return (datetime.now(UTC) - ts).total_seconds() / 3600


def profile_cluster() -> ClusterProfile:
    core, apps, storage, version_api = kube_clients()
    prof = ClusterProfile()

    try:
        info = version_api.get_code()
        prof.version = f"{info.git_version} ({info.platform})"
    except client.ApiException:
        pass

    for node in core.list_node().items:
        labels = node.metadata.labels or {}
        roles = sorted(
            key.split("/", 1)[1]
            for key in labels
            if key.startswith("node-role.kubernetes.io/")
        )
        prof.nodes.append(
            {
                "name": node.metadata.name,
                "arch": labels.get("kubernetes.io/arch", "?"),
                "roles": ",".join(roles) or "worker",
                "os": node.status.node_info.os_image if node.status.node_info else "?",
                "ready": next(
                    (c.status for c in node.status.conditions or [] if c.type == "Ready"),
                    "?",
                ),
                "taints": ",".join(
                    f"{t.key}={t.effect}" for t in (node.spec.taints or [])
                ),
            }
        )
    prof.architectures = sorted({n["arch"] for n in prof.nodes})

    workloads: list[tuple[str, str]] = [
        (w.metadata.name, w.metadata.namespace)
        for lister in (
            apps.list_deployment_for_all_namespaces,
            apps.list_daemon_set_for_all_namespaces,
            apps.list_stateful_set_for_all_namespaces,
        )
        for w in lister().items
    ]

    for name, namespace in workloads:
        if (label := _bucket(name, _INGRESS_SIGNS)) and label not in dict(prof.ingress):
            prof.ingress.append((label, namespace))
        if (
            label := _bucket(name, _OBSERVABILITY_SIGNS)
        ) and label not in prof.observability:
            prof.observability.append(label)
        if (label := _bucket(name, _GITOPS_SIGNS)) and label not in prof.gitops:
            prof.gitops.append(label)

    prof.absent = sorted(
        (set(_OBSERVABILITY_SIGNS.values()) - set(prof.observability))
        | (set(_GITOPS_SIGNS.values()) - set(prof.gitops))
    )

    try:
        for sc in storage.list_storage_class().items:
            if sc.provisioner not in prof.provisioners:
                prof.provisioners.append(sc.provisioner)
            annotations = sc.metadata.annotations or {}
            if annotations.get("storageclass.kubernetes.io/is-default-class") == "true":
                prof.default_storage_class = sc.metadata.name
    except client.ApiException:
        pass

    # Name the CSI driver's own pods, so the storage investigator knows what to
    # read logs from instead of guessing a vendor-specific pod name.
    names = {name for name, _ in workloads}
    for driver, pods in _CSI_HINTS.items():
        if any(p in n for n in names for p in pods) or any(
            driver in prov for prov in prof.provisioners
        ):
            present = sorted(n for n in names if any(p in n for p in pods))
            if present:
                prof.csi_workloads.append(f"{driver}: {', '.join(present)}")

    system_prefixes = ("kube-", "openshift-", "cattle-", "gatekeeper-", "tigera-")
    pods = core.list_pod_for_all_namespaces().items
    prof.workload_namespaces = sorted(
        {
            p.metadata.namespace
            for p in pods
            if not p.metadata.namespace.startswith(system_prefixes)
            and p.metadata.namespace != "default"
        }
    )

    # Restart baseline. A cohort of pods sharing a restart age is one host
    # event, not the incident. Surfacing the number lets the critic reject it.
    ages: Counter[int] = Counter()
    for pod in pods:
        for status in pod.status.container_statuses or []:
            if not status.restart_count:
                continue
            terminated = status.last_state.terminated if status.last_state else None
            hours = _hours_since(terminated.finished_at if terminated else None)
            if hours is not None and hours >= 1:
                ages[round(hours)] += 1
    threshold = max(3, len(pods) // 4)
    prof.baseline_restarts = [
        f"{count} containers last restarted about {hours}h ago"
        for hours, count in ages.most_common(3)
        if count >= threshold
    ]
    return prof


def render_facts(prof: ClusterProfile) -> str:
    """The <cluster> block injected into every prompt. All of it is measured."""
    lines = ["<cluster>", f"Kubernetes {prof.version}, {prof.node_count} node(s)."]
    for node in prof.nodes:
        taints = f" taints={node['taints']}" if node["taints"] else ""
        lines.append(
            f"  {node['name']:<22} {node['arch']:<7} {node['roles']:<22}"
            f" ready={node['ready']} os={node['os']}{taints}"
        )

    lines.append("")
    if prof.heterogeneous:
        lines += [
            "HETEROGENEOUS ARCHITECTURE: this cluster mixes "
            + " and ".join(prof.architectures)
            + ". Image architecture mismatch is a first-class hypothesis for any",
            "container that dies instantly on some nodes but not others.",
        ]
    else:
        arch = prof.architectures[0] if prof.architectures else "unknown"
        lines.append(
            f"All nodes are {arch}. An image architecture mismatch would fail on "
            "every node equally, never on a subset."
        )

    lines.append("")
    lines.append(
        "Ingress controller(s): "
        + (
            ", ".join(f"{name} (namespace {ns})" for name, ns in prof.ingress)
            or "none detected. There may be no HTTP ingress path at all, so do "
            "not assume one exists."
        )
    )
    lines.append(
        "Storage provisioners: "
        + (", ".join(prof.provisioners) or "none")
        + (
            f". Default class: {prof.default_storage_class}"
            if prof.default_storage_class
            else ""
        )
    )
    if prof.csi_workloads:
        lines.append(
            "CSI driver workloads to read logs from: " + "; ".join(prof.csi_workloads)
        )
    lines.append("Observability present: " + (", ".join(prof.observability) or "nothing"))
    lines.append("GitOps present: " + (", ".join(prof.gitops) or "nothing"))
    if prof.absent:
        lines.append(
            "NOT present, so no evidence can possibly come from it: "
            + ", ".join(prof.absent)
            + ". Never cite these systems."
        )
    lines.append(
        "Non-system namespaces: " + (", ".join(prof.workload_namespaces) or "none")
    )
    lines.append("</cluster>")

    if prof.baseline_restarts:
        lines += [
            "",
            "<known-baseline-noise>",
            "A large cohort of pods shares one restart age, which indicates a "
            "single host or control-plane event rather than an incident:",
            *(f"  {row}" for row in prof.baseline_restarts),
            "Treat that cohort as baseline. 'The node restarted' is a "
            "NON-explanation unless a restart timestamp falls inside the",
            "reported symptom window.",
            "</known-baseline-noise>",
        ]
    return "\n".join(lines)


def render_routing(prof: ClusterProfile) -> str:
    """Status-code mechanics, written for whichever controller is installed."""
    controller = prof.controller
    if controller is None:
        return """\
<routing-mechanics>
No ingress controller was detected in this cluster. Reason at the Service
level only:
  * No Ready pod -> the EndpointSlice has no serving endpoint -> a client
    connecting through the Service gets no backend at all.
  * Pod Ready but Service.targetPort points at a port nothing listens on ->
    the connection is actively refused.
These are different failures with different fixes. Do not conflate them, and
do not invent HTTP status codes when nothing terminates HTTP.
</routing-mechanics>"""

    missing, refused = _ROUTING_SEMANTICS.get(controller, ("503", "502"))
    return f"""\
<routing-mechanics>
This cluster's ingress is {controller}. Reason precisely about these, they are
routinely confused:
  * No Ready pod -> the EndpointSlice has no serving endpoint -> {controller}
    has no backend to dial -> HTTP {missing}.
  * Pod Ready but Service.targetPort points at a port nothing listens on ->
    {controller} dials it and the connection is refused -> HTTP {refused}.
  * A failing readinessProbe yields {missing}, never {refused}: an unready pod
    is removed from the serving endpoints, so nothing is ever dialled.
  * Deriving {refused} from an empty EndpointSlice is a factual error.
</routing-mechanics>"""
