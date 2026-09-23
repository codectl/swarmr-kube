"""Reading this team's tool results: one-line summary, and what counts as failure.

Domain knowledge, so it lives with the team: only the Kubernetes team knows that
a payload with `count` and `items` is an object list, that `platforms` comes from
a registry manifest lookup, that a log tail's newest line is the interesting one,
or that its own tools report trouble by opening with "tool error" or "no logs".
`core` gets a shape-only fallback, marks nothing as an error, and stays
domain-free.
"""

from __future__ import annotations

import json

from swarmr.core.text import clip

__all__ = ["digest_result", "is_tool_error"]

# How this team's tools say "that did not work". `guard` writes the first; the
# read tools write the others when a query matched nothing.
_ERROR_PREFIXES = ("tool error", "no logs", "no match", "No ")


def is_tool_error(text: str) -> bool:
    """Whether a tool result is a failure rather than an observation."""
    return text.strip().startswith(_ERROR_PREFIXES)


def digest_result(text: str) -> str:
    """One informative line for a cluster tool result.

    A byte count plus the first line is worthless here: every JSON result opens
    with "{". What a reader wants is which kind came back, how many, or the
    error.
    """
    stripped = text.strip()
    if not stripped:
        return "empty"
    if is_tool_error(stripped):
        return clip(stripped, 100)
    if stripped.startswith("{"):
        return _digest_json(stripped, len(text))
    lines = [line for line in stripped.splitlines() if line.strip()]
    # Log output: the newest line matters, and the leading timestamps do not.
    newest = lines[-1] if lines else ""
    for token in newest.split(" "):
        if token and not token[0].isdigit():
            newest = newest[newest.index(token) :]
            break
    return f"{len(lines)} log lines | …{clip(newest, 70)}"


def _digest_json(stripped: str, size: int) -> str:
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return f"{size}B truncated json"
    kind = data.get("kind", "")
    # Order matters: an events payload also carries "count", so the more
    # specific shapes must be tested before the generic list shape.
    if "events" in data:
        events = data["events"]
        warnings = [e for e in events if e.get("type") == "Warning"]
        reasons = sorted({e.get("reason", "") for e in warnings})
        tail = f" [{', '.join(reasons[:3])}]" if reasons else ""
        return f"{len(events)} events, {len(warnings)} warning{tail}"
    if "platforms" in data:
        return f"platforms {', '.join(data['platforms'])}"
    if "usage" in data:
        return f"usage for {data.get('count', '?')} {data.get('scope', '')}"
    if "count" in data:
        names = [
            str(item["name"])
            for item in (data.get("items") or [])
            if isinstance(item, dict) and item.get("name")
        ]
        listed = ", ".join(names[:3]) + (" +…" if len(names) > 3 else "")
        return f"{kind or 'object'} x{data['count']}" + (f" [{listed}]" if listed else "")
    name = data.get("name") or (data.get("metadata") or {}).get("name", "")
    return f"{kind}/{name}" if name else f"{kind or 'object'} object"
