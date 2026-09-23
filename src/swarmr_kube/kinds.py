"""Turning whatever kind a model wrote into a real API resource.

One responsibility: normalisation. Discovery is exact-match, while models write
kinds in any case and plurality ("volumeattachment", "EndpointSlices",
"ingressroutes") and reach for kubectl abbreviations ("deploy", "pvc"). Every
alias is resolved against live discovery rather than a hand-maintained table,
which would rot and would miss CRDs entirely.
"""

from __future__ import annotations

from functools import cache
from typing import Any

from swarmr_kube.client import dynamic_api

__all__ = ["resolve_kind"]


@cache
def _short_names() -> dict[str, Any]:
    """Map every shortName the API server publishes to its resource.

    Built once from discovery, so CRD abbreviations work too and there is no
    hand-maintained alias table to fall out of date.
    """
    index: dict[str, Any] = {}
    for resource in dynamic_api().resources.search():
        if resource.kind.endswith("List"):
            continue
        for short in getattr(resource, "short_names", None) or ():
            index.setdefault(short.lower(), resource)
    return index


def _by_short_name(lowered: str) -> Any | None:
    return _short_names().get(lowered)


@cache
def resolve_kind(kind: str) -> Any:
    """Resolve a Kind across every API group, CRDs included.

    Models write kinds in whatever case and plurality they like
    ("volumeattachment", "EndpointSlices", "ingressroutes"). Discovery is
    exact-match, so normalise here rather than making the model guess.
    """
    api = dynamic_api()
    stem = kind.strip()
    candidates = [stem, stem[:1].upper() + stem[1:]]
    if stem.lower().endswith("s"):
        singular = stem[:-1]
        candidates += [singular, singular[:1].upper() + singular[1:]]

    for candidate in candidates:
        try:
            if matches := api.resources.search(kind=candidate):
                # Several groups can serve one Kind; prefer the shortest group,
                # which is the canonical one rather than a deprecated alias.
                return sorted(matches, key=lambda r: (len(r.group or ""), r.name))[0]
        except Exception:
            continue

    # Fall back to the plural resource name, always lowercase in discovery
    # ("volumeattachments"). This rescues camel-cased kinds written lowercase.
    lowered = stem.lower()
    for name in (lowered, lowered + "s", lowered.rstrip("s"), lowered + "es"):
        try:
            matches = [
                r for r in api.resources.search(name=name) if not r.kind.endswith("List")
            ]
            if matches:
                return matches[0]
        except Exception:
            continue

    # Finally the kubectl abbreviations ("deploy", "pvc", "sc", "ep"). The API
    # server publishes these as shortNames, so ask it rather than hardcoding a
    # table that would rot and would miss CRDs.
    if resource := _by_short_name(lowered):
        return resource

    raise ValueError(
        f"unknown kind {kind!r}. Use a Kubernetes Kind such as Pod, Service, "
        "EndpointSlice, Deployment, PersistentVolumeClaim, StorageClass, "
        "VolumeAttachment, Node, Ingress, or a CRD Kind this cluster serves."
    )
