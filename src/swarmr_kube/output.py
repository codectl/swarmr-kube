"""Shaping what a tool returns: pruning, byte-capping, error containment, caching.

One responsibility: everything that happens to a tool result on its way back to
a subagent, and nothing about how the result was obtained. Raw Kubernetes JSON
is mostly server bookkeeping, an unhandled exception inside a tool kills the
whole run, and four investigators reading one incident issue the same call, so
every tool wears the same three wrappers.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from functools import wraps
from typing import Any

from kubernetes import client

from swarmr_kube.client import CredentialError

__all__ = ["CACHE_TTL", "MAX_BYTES", "cached", "emit", "guard"]

MAX_BYTES = 12_000
CACHE_TTL = float(os.environ.get("INCIDENT_CACHE_TTL", "45"))

_STRIP_META = (
    "managedFields",
    "resourceVersion",
    "uid",
    "generation",
    "selfLink",
    "creationTimestamp",
    "finalizers",
    # ownerReferences is deliberately kept: it is how a subagent walks
    # pod -> replicaset -> deployment without guessing from labels.
)
_STRIP_ANNOTATIONS = (
    "kubectl.kubernetes.io/last-applied-configuration",
    "deployment.kubernetes.io/revision",
)


def _prune(obj: Any) -> Any:
    """Drop server bookkeeping that carries no diagnostic signal."""
    if isinstance(obj, list):
        return [_prune(item) for item in obj]
    if not isinstance(obj, dict):
        return obj
    out = {
        k: _prune(v)
        for k, v in obj.items()
        if v not in (None, [], {}) and k not in _STRIP_META
    }
    meta = out.get("metadata")
    if isinstance(meta, dict):
        annotations = {
            k: v
            for k, v in (meta.get("annotations") or {}).items()
            if k not in _STRIP_ANNOTATIONS
        }
        meta = {k: v for k, v in meta.items() if k != "annotations"}
        if annotations:
            meta["annotations"] = annotations
        out["metadata"] = meta
    return out


def emit(payload: Any) -> str:
    """Serialise a tool result, pruned and byte-capped."""
    text = json.dumps(_prune(payload), indent=1, default=str, sort_keys=False)
    if len(text) <= MAX_BYTES:
        return text
    return (
        text[:MAX_BYTES] + f"\n... TRUNCATED at {MAX_BYTES} bytes. Narrow the query "
        "(pass `name`, or a single namespace) instead of listing everything."
    )


def guard(fn: Callable[..., str]) -> Callable[..., str]:
    """Turn any tool failure into a message the model can act on.

    An unhandled exception inside a tool aborts the whole LangGraph run and
    takes every concurrent investigator down with it. A bad argument is not a
    fatal condition; it is feedback. Return it as text and let the agent retry.

    Naming the specialist behind a stream id used to happen here as well, off a
    process-global map. It does not any more: `core.middleware.AnnounceName`
    announces on the subagent's first model call, which always precedes its
    first tool call, and it carries the run's own `Attribution`.
    """

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> str:
        try:
            return fn(*args, **kwargs)
        except ValueError as exc:
            return f"tool error: {exc}"
        except CredentialError as exc:
            # Fatal for every other call too, so it is reported as the sentence
            # it is rather than as `CredentialError: ...` through the catch-all.
            return f"tool error: {exc}"
        except client.ApiException as exc:
            reason = (exc.reason or "").strip()
            if exc.status == 403:
                return (
                    f"tool error: forbidden ({reason}). This credential is read-only "
                    "by design; the object may also not exist."
                )
            if exc.status == 404:
                return f"tool error: not found ({reason}). Check name and namespace."
            return f"tool error: HTTP {exc.status} {reason}"
        except Exception as exc:
            return f"tool error: {type(exc).__name__}: {exc}"

    return wrapper


_cache: dict[str, tuple[float, str]] = {}


def cached(fn: Callable[..., str]) -> Callable[..., str]:
    """Memoise identical reads for a short window.

    Investigators run concurrently on one incident, so they independently issue
    the same k_get and k_events calls. Each duplicate costs a round trip and a
    full result's worth of tokens. The TTL is deliberately short: an incident is
    a moving target and a stale endpoint list is worse than a slow one. Set
    INCIDENT_CACHE_TTL=0 to disable.
    """

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> str:
        if CACHE_TTL <= 0:
            return fn(*args, **kwargs)
        key = f"{fn.__name__}|{args!r}|{sorted(kwargs.items())!r}"
        now = time.monotonic()
        if hit := _cache.get(key):
            stamped, value = hit
            if now - stamped < CACHE_TTL:
                return value
        value = fn(*args, **kwargs)
        _cache[key] = (now, value)
        return value

    return wrapper
