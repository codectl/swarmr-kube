"""The broad cluster reads, and the tool set each role is given.

One responsibility: the general-purpose Kubernetes reads (list, events, logs,
usage) plus the per-role tool sets assembled from them. The two tools carrying
their own specialised knowledge live next door: `describe.py` knows which
fields matter per kind, `registry.py` talks to a container registry rather than
to Kubernetes.

Design rules:
  * No shell, and no kubectl string synthesis. The model picks a tool and typed
    arguments; the tool builds the API call. Nothing the model emits reaches a
    shell.
  * Every call rides a ServiceAccount credential holding only get/list/watch.
    The boundary is the credential, not the prompt.
  * Output is projected and byte-capped, because raw Kubernetes JSON is mostly
    bookkeeping and burns the subagent's context.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from kubernetes import client
from langchain_core.tools import tool

from swarmr_kube.client import core_api, custom_api
from swarmr_kube.describe import k_describe
from swarmr_kube.kinds import resolve_kind
from swarmr_kube.output import MAX_BYTES, cached, emit, guard
from swarmr_kube.projection import age, clean_log, digest
from swarmr_kube.registry import image_platforms

__all__ = [
    "CRITIC_TOOLS",
    "INVESTIGATOR_TOOLS",
    "PLATFORM_TOOLS",
    "k_events",
    "k_get",
    "k_logs",
    "k_top",
]


@tool(parse_docstring=True)
@guard
@cached
def k_get(
    kind: str,
    ns: str | None = None,
    name: str | None = None,
    selector: str | None = None,
) -> str:
    """Fetch Kubernetes objects.

    Without `name` you get one compact row per object: enough to tell which
    object is suspect. With `name` you get the full object. Works for any kind
    including CRDs. Follow up on a suspect with k_describe, which adds events.

    Args:
        kind: Object kind or alias, e.g. "pod", "svc", "endpointslice", "node".
        ns: Namespace. Omit for cluster-scoped kinds or to search all namespaces.
        name: Exact object name. Omit to list.
        selector: Label selector matching the object's OWN labels, e.g.
            "app=checkout" for pods carrying that label. It does NOT match a
            Service's spec.selector: a Service that selects app=checkout usually
            carries no such label itself, so filtering Services or Ingresses this
            way returns zero and means nothing. List them without a selector and
            read spec.selector instead. For the EndpointSlices of a Service, the
            selector you want is "kubernetes.io/service-name=<service>".
    """
    resource = resolve_kind(kind)
    kwargs: dict[str, Any] = {}
    if resource.namespaced and ns:
        kwargs["namespace"] = ns
    if name:
        kwargs["name"] = name
    if selector:
        kwargs["label_selector"] = selector
    obj = resource.get(**kwargs).to_dict()
    if "items" not in obj:
        return emit(obj)
    return emit(
        {
            "kind": resource.kind,
            "count": len(obj["items"]),
            "note": "compact rows; call k_get with name= for the full object",
            "items": [digest(resource.kind, item) for item in obj["items"]],
        }
    )


@tool(parse_docstring=True)
@guard
@cached
def k_events(
    ns: str | None = None, since: str = "30m", warnings_only: bool = False
) -> str:
    """List recent cluster events, newest last.

    Usually the highest-signal source: image pull failures, probe failures,
    volume mount failures and scheduling refusals all surface here with a
    reason code.

    Args:
        ns: Namespace to scope to. Omit for all namespaces.
        since: Lookback window, e.g. "5m", "30m", "2h".
        warnings_only: Keep only type=Warning events.
    """
    unit = since[-1]
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(unit, 60)
    window = int(since[:-1] or 30) * multiplier
    cutoff = datetime.now(UTC) - timedelta(seconds=window)

    api = core_api()
    raw = (
        api.list_namespaced_event(ns, limit=500)
        if ns
        else api.list_event_for_all_namespaces(limit=500)
    )
    rows = []
    for event in raw.items:
        stamp = event.last_timestamp or event.event_time
        if stamp and stamp < cutoff:
            continue
        if warnings_only and event.type != "Warning":
            continue
        rows.append(
            {
                "age": age(stamp),
                "type": event.type,
                "ns": event.metadata.namespace,
                "object": f"{event.involved_object.kind}/{event.involved_object.name}",
                "reason": event.reason,
                "count": event.count,
                "message": (event.message or "")[:300],
            }
        )
    rows.sort(key=lambda r: r["age"], reverse=True)
    return emit({"window": since, "count": len(rows), "events": rows})


@tool(parse_docstring=True)
@guard
@cached
def k_logs(
    ns: str,
    pod: str,
    container: str | None = None,
    previous: bool = False,
    tail: int = 60,
) -> str:
    """Read container logs, de-coloured and with repeated lines collapsed.

    For a crash-looping pod the useful logs are in the *previous* container
    instance: pass previous=True. A crashed container often logs nothing at
    all, which is itself evidence that the process never started.

    Args:
        ns: Namespace.
        pod: Pod name.
        container: Container name. Omit when the pod has one container.
        previous: Read the previous terminated instance instead of the current one.
        tail: Number of trailing lines.
    """
    try:
        text = core_api().read_namespaced_pod_log(
            name=pod,
            namespace=ns,
            container=container,
            previous=previous,
            tail_lines=tail,
            timestamps=True,
        )
    except client.ApiException as exc:
        if exc.status == 404:
            return (
                f"no logs: pod {pod!r} not found in namespace {ns!r}. Pass an exact "
                "pod name; list them first with k_get."
            )
        return f"no logs: HTTP {exc.status} {(exc.reason or '').strip()}"
    if not text.strip():
        return (
            f"{pod}: log stream empty (previous={previous}). The container produced "
            "no output, consistent with a process that failed before it could log, "
            "for example a runtime or exec failure."
        )
    return clean_log(text)[-MAX_BYTES:]


@tool(parse_docstring=True)
@guard
@cached
def k_top(scope: str = "nodes", ns: str | None = None) -> str:
    """Read live CPU and memory usage from metrics-server.

    Args:
        scope: "nodes" or "pods".
        ns: Namespace, when scope="pods". Omit for all namespaces.
    """
    api = custom_api()
    group, version = "metrics.k8s.io", "v1beta1"
    try:
        if scope.startswith("node"):
            data = api.list_cluster_custom_object(group, version, "nodes")
            rows = [{"node": i["metadata"]["name"], **i["usage"]} for i in data["items"]]
        elif ns:
            data = api.list_namespaced_custom_object(group, version, ns, "pods")
            rows = [
                {
                    "pod": i["metadata"]["name"],
                    "containers": {c["name"]: c["usage"] for c in i["containers"]},
                }
                for i in data["items"]
            ]
        else:
            data = api.list_cluster_custom_object(group, version, "pods")
            rows = [
                {
                    "ns": i["metadata"]["namespace"],
                    "pod": i["metadata"]["name"],
                    "containers": {c["name"]: c["usage"] for c in i["containers"]},
                }
                for i in data["items"]
            ]
    except client.ApiException as exc:
        return f"metrics unavailable: HTTP {exc.status}"
    return emit({"scope": scope, "count": len(rows), "usage": rows})


# Tool sets per role. Only `platform` and `critic` get image_platforms, because
# only they are asked to make or check an architecture claim.
INVESTIGATOR_TOOLS = [k_get, k_describe, k_events, k_logs]
PLATFORM_TOOLS = [k_get, k_describe, k_events, k_top, image_platforms]
CRITIC_TOOLS = [k_get, k_describe, k_events, k_logs, k_top, image_platforms]
