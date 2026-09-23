"""The one deep read: `k_describe`, and the per-kind knowledge it needs.

One responsibility: describing a single suspect object. It is the only tool that
carries kind-specific field knowledge (which fields of a Pod, Service or Node
decide a diagnosis) and the only one that correlates an object's status with the
events the control plane emitted about it, so it owns both here instead of
bloating the general tool surface in `tools.py`.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import tool

from swarmr_kube.client import core_api
from swarmr_kube.kinds import resolve_kind
from swarmr_kube.output import cached, emit, guard
from swarmr_kube.projection import age

__all__ = ["k_describe"]


@tool(parse_docstring=True)
@guard
@cached
def k_describe(kind: str, name: str, ns: str | None = None) -> str:
    """Summarise one object: spec highlights, conditions, and its recent events.

    The highest-signal first call for a suspect object: it correlates the
    object's status with the events the control plane emitted about it, so a
    separate k_events call for the same object is redundant.

    Args:
        kind: Object kind or alias, e.g. "pod", "deploy", "pvc".
        name: Exact object name.
        ns: Namespace. Omit for cluster-scoped kinds.
    """
    resource = resolve_kind(kind)
    kwargs: dict[str, Any] = {"name": name}
    if resource.namespaced and ns:
        kwargs["namespace"] = ns
    obj = resource.get(**kwargs).to_dict()
    meta = obj.get("metadata") or {}
    spec = obj.get("spec") or {}
    status = obj.get("status") or {}

    summary: dict[str, Any] = {
        "kind": resource.kind,
        "name": meta.get("name"),
        "namespace": meta.get("namespace"),
        "labels": meta.get("labels"),
        "age": age(meta.get("creationTimestamp")),
        "conditions": [
            {k: c.get(k) for k in ("type", "status", "reason", "message") if c.get(k)}
            for c in (status.get("conditions") or [])
        ],
    }
    summary |= _highlights(resource.kind, meta, spec, status)
    summary["events"] = _events_for(meta.get("namespace"), name)
    return emit(summary)


def _highlights(
    kind: str, meta: dict[str, Any], spec: dict[str, Any], status: dict[str, Any]
) -> dict[str, Any]:
    """The fields that decide a diagnosis for this kind.

    A Pod is judged on its containers and their last exit, a Service on the port
    mapping, a Node on architecture and taints. Anything else gets the whole
    spec, because guessing which of a CRD's fields matter is worse than paying
    for all of them.
    """
    if kind == "Pod":
        return {
            "node": spec.get("nodeName"),
            "phase": status.get("phase"),
            "nodeSelector": spec.get("nodeSelector"),
            "containers": [
                {
                    "name": c.get("name"),
                    "image": c.get("image"),
                    "ports": c.get("ports"),
                    "readinessProbe": c.get("readinessProbe"),
                    "livenessProbe": c.get("livenessProbe"),
                }
                for c in spec.get("containers", [])
            ],
            "containerStatuses": [
                {
                    "name": cs.get("name"),
                    "ready": cs.get("ready"),
                    "restartCount": cs.get("restartCount"),
                    "image": cs.get("image"),
                    "state": cs.get("state"),
                    "lastState": cs.get("lastState"),
                }
                for cs in (status.get("containerStatuses") or [])
            ],
        }
    if kind == "Service":
        return {
            "type": spec.get("type"),
            "selector": spec.get("selector"),
            "ports": spec.get("ports"),
            "publishNotReadyAddresses": spec.get("publishNotReadyAddresses"),
        }
    if kind == "Node":
        return {
            "arch": (meta.get("labels") or {}).get("kubernetes.io/arch"),
            "taints": spec.get("taints"),
            "allocatable": status.get("allocatable"),
            "nodeInfo": status.get("nodeInfo"),
        }
    return {
        "spec": spec,
        "status": {k: v for k, v in status.items() if k != "conditions"},
    }


def _events_for(ns: str | None, name: str) -> list[dict[str, Any]]:
    field = f"involvedObject.name={name}"
    api = core_api()
    raw = (
        api.list_namespaced_event(ns, field_selector=field, limit=25)
        if ns
        else api.list_event_for_all_namespaces(field_selector=field, limit=25)
    )
    return [
        {
            "type": e.type,
            "reason": e.reason,
            "count": e.count,
            "age": age(e.last_timestamp or e.event_time),
            "message": (e.message or "")[:400],
        }
        for e in raw.items
    ]
