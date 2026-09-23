"""Turning raw Kubernetes objects into something worth spending tokens on.

Full objects are 4-10 KB each, so a three-pod list overruns any sane byte cap
and truncates mid-object — hiding the very field being looked for. A list
answers "which object is suspect"; `k_describe` then answers "why".
"""

from __future__ import annotations

import ast
import re
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

__all__ = ["age", "clean_log", "container_state", "digest"]

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_WORKLOAD_KINDS = ("Deployment", "StatefulSet", "ReplicaSet", "DaemonSet")


def age(timestamp: Any) -> str:
    """Human-readable age. Absolute timestamps are noise in a summary."""
    if not timestamp:
        return "?"
    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    seconds = int((datetime.now(UTC) - timestamp).total_seconds())
    if seconds < 120:
        return f"{seconds}s"
    if seconds < 7200:
        return f"{seconds // 60}m"
    if seconds < 172800:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def container_state(state: dict[str, Any] | None) -> str:
    """Collapse a container state object into one diagnostic token."""
    if not state:
        return "?"
    if waiting := state.get("waiting"):
        return f"Waiting/{waiting.get('reason', '?')}"
    if terminated := state.get("terminated"):
        reason = terminated.get("reason", "?")
        return f"Terminated/{reason}(exit={terminated.get('exitCode')})"
    if "running" in state:
        return "Running"
    return "?"


def clean_log(raw: str) -> str:
    """Undo two forms of waste in the client's log output.

    The Kubernetes client hands back a str that is really the *repr* of bytes:
    it literally begins b' and contains escape sequences as six characters
    each. Left alone, a colourised log spends more tokens on colour than on
    words. Runs of identical lines are also collapsed, since a probe hitting the
    same endpoint sixty times says nothing new after the first.
    """
    if raw.startswith(("b'", 'b"')):
        with suppress(ValueError, SyntaxError, AttributeError):
            raw = ast.literal_eval(raw).decode("utf-8", "replace")
    raw = raw.replace("\\n", "\n").replace("\\t", "\t")
    raw = _ANSI_RE.sub("", raw).replace("\\x1b", "")

    out: list[str] = []
    previous: str | None = None
    repeats = 0
    for line in raw.splitlines():
        # Timestamps make every line unique, so compare the message only.
        body = line.split(" ", 1)[1] if " " in line else line
        if body == previous:
            repeats += 1
            continue
        if repeats:
            out.append(f"    ... previous line repeated {repeats}x")
            repeats = 0
        out.append(line)
        previous = body
    if repeats:
        out.append(f"    ... previous line repeated {repeats}x")
    return "\n".join(out)


def digest(kind: str, obj: dict[str, Any]) -> dict[str, Any]:
    """One compact row per object, carrying the fields that decide a diagnosis."""
    meta = obj.get("metadata") or {}
    spec = obj.get("spec") or {}
    status = obj.get("status") or {}
    row: dict[str, Any] = {"name": meta.get("name")}
    if meta.get("namespace"):
        row["ns"] = meta.get("namespace")
    row["age"] = age(meta.get("creationTimestamp"))

    if kind == "Pod":
        row |= _pod(spec, status)
    elif kind == "Node":
        row |= _node(meta, spec, status)
    elif kind == "Service":
        row |= _service(spec)
    elif kind == "EndpointSlice":
        row |= _endpoint_slice(obj)
    elif kind in _WORKLOAD_KINDS:
        row |= _workload(spec, status)
    elif kind == "PersistentVolumeClaim":
        row |= _claim(spec, status)
    else:
        row |= _generic(spec, status)
    return {k: v for k, v in row.items() if v not in (None, [], {})}


def _pod(spec: dict[str, Any], status: dict[str, Any]) -> dict[str, Any]:
    statuses = status.get("containerStatuses") or []
    declared = spec.get("containers") or []
    row: dict[str, Any] = {
        "node": spec.get("nodeName"),
        "phase": status.get("phase"),
        "ready": f"{sum(1 for c in statuses if c.get('ready'))}/{len(declared)}",
        "restarts": sum(c.get("restartCount") or 0 for c in statuses),
        "containers": {
            c.get("name"): {
                "image": c.get("image"),
                "state": container_state(c.get("state")),
                "last": container_state(c.get("lastState")),
            }
            for c in statuses
        }
        or {c.get("name"): {"image": c.get("image")} for c in declared},
    }
    if spec.get("nodeSelector"):
        row["nodeSelector"] = spec["nodeSelector"]
    unscheduled = [
        c.get("message")
        for c in status.get("conditions") or []
        if c.get("type") == "PodScheduled" and c.get("status") == "False"
    ]
    if unscheduled:
        row["notScheduled"] = unscheduled[0]
    return row


def _node(
    meta: dict[str, Any], spec: dict[str, Any], status: dict[str, Any]
) -> dict[str, Any]:
    return {
        "arch": (meta.get("labels") or {}).get("kubernetes.io/arch"),
        "ready": next(
            (
                c.get("status")
                for c in status.get("conditions") or []
                if c.get("type") == "Ready"
            ),
            "?",
        ),
        "taints": spec.get("taints"),
        "allocatable": status.get("allocatable"),
    }


def _service(spec: dict[str, Any]) -> dict[str, Any]:
    ports = [
        {
            key: value
            for key, value in (
                ("port", p.get("port")),
                ("targetPort", p.get("targetPort")),
                ("protocol", p.get("protocol")),
            )
            if value is not None
        }
        for p in spec.get("ports") or []
    ]
    return {
        "type": spec.get("type"),
        "selector": spec.get("selector"),
        "ports": ports,
    }


def _endpoint_slice(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "ports": [p.get("port") for p in obj.get("ports") or []],
        "endpoints": [
            {
                "addresses": e.get("addresses"),
                "ready": (e.get("conditions") or {}).get("ready"),
                "serving": (e.get("conditions") or {}).get("serving"),
                "node": e.get("nodeName"),
            }
            for e in obj.get("endpoints") or []
        ],
    }


def _workload(spec: dict[str, Any], status: dict[str, Any]) -> dict[str, Any]:
    template_spec = (spec.get("template") or {}).get("spec") or {}
    return {
        "desired": spec.get("replicas", spec.get("desiredNumberScheduled")),
        "ready": status.get("readyReplicas", status.get("numberReady", 0)),
        "unavailable": status.get("unavailableReplicas", status.get("numberUnavailable")),
        "images": [c.get("image") for c in template_spec.get("containers") or []],
        "notReady": [
            f"{c.get('type')}={c.get('reason')}: {c.get('message')}"
            for c in status.get("conditions") or []
            if c.get("status") == "False"
        ],
    }


def _claim(spec: dict[str, Any], status: dict[str, Any]) -> dict[str, Any]:
    return {
        "phase": status.get("phase"),
        "storageClass": spec.get("storageClassName"),
        "volume": spec.get("volumeName"),
        "request": ((spec.get("resources") or {}).get("requests") or {}).get("storage"),
    }


def _generic(spec: dict[str, Any], status: dict[str, Any]) -> dict[str, Any]:
    return {
        "spec": spec or None,
        "conditions": [
            {k: c.get(k) for k in ("type", "status", "reason") if c.get(k)}
            for c in status.get("conditions") or []
        ]
        or None,
        "phase": status.get("phase"),
    }
