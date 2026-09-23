"""The report the commander files at the end of an investigation.

One responsibility: the shape of a filed report — the tool the commander calls
and the plain-text rendering of its arguments. What may not appear in that text
is policy, and lives in `redaction.py`.

Two failure modes made prose-only reporting unreliable:
  * The commander sometimes stops after the critic's verdict, leaving the caller
    with verdicts but no findings.
  * A provider may return content blocks rather than a string, which naive text
    extraction discards.

`response_format=ToolStrategy(...)` would solve it, but it sets
`tool_choice="required"`, which this model rejects outright while thinking is
enabled ("tool_choice 'required' is incompatible with thinking enabled"). So the
report is a normal tool the commander is instructed to call. Its arguments are
visible in the update stream, which makes the filing deterministic to capture
and visible in the delegation trail.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import tool

from swarmr_kube.redaction import (
    LOCATION_CAVEAT,
    OMITTED_NOTE,
    diagnosis,
    locator,
    one_line,
)

__all__ = ["FILE_REPORT_TOOL", "render_report_args"]


def render_report_args(args: dict[str, Any]) -> str:
    """Render filed report arguments as plain text."""
    symptom = str(args.get("symptom") or "").strip()
    root_cause = str(args.get("root_cause") or "").strip()
    lines: list[str] = []
    if symptom:
        lines += ["SYMPTOM", symptom, ""]
    chain, pruned = diagnosis(root_cause)
    if pruned and not chain:
        chain = "withheld; see EVIDENCE and WHERE TO FIX IT"
    lines += ["ROOT CAUSE", chain or "none found"]
    if pruned:
        lines += [OMITTED_NOTE]

    for label, key in (("EVIDENCE", "evidence"), ("DISMISSED", "dismissed")):
        items = args.get(key) or []
        if isinstance(items, str):
            items = [items]
        if items:
            lines += ["", label, *(f"  - {str(item).strip()}" for item in items)]

    if ruling := str(args.get("critic_ruling") or "").strip():
        lines += ["", "CRITIC RULING", f"  {ruling}"]
    obj = one_line(args.get("fix_object"))
    where = locator(args.get("fix_locator"))
    if obj or where:
        located = " — ".join(part for part in (obj, where) if part)
        lines += ["", "WHERE TO FIX IT", f"  {located}", LOCATION_CAVEAT]
    return "\n".join(lines)


@tool(parse_docstring=True)
def file_incident_report(
    symptom: str,
    root_cause: str,
    evidence: list[str],
    critic_ruling: str = "",
    fix_object: str = "",
    fix_locator: str = "",
    dismissed: list[str] | None = None,
) -> str:
    """File the final incident report. Call this exactly once, as your last action.

    Args:
        symptom: The reported symptom, restated in one or two sentences.
        root_cause: The causal chain from the underlying condition to the
            observed symptom, naming objects and field values. Use exactly
            "none found" when the cluster is healthy.
        evidence: One line per fact, each naming a real object and a real value,
            attributed to the specialist that observed it, for example
            "Service demo/payments: port 80 -> targetPort 8081 (network)".
        critic_ruling: The critic's verbatim ruling: confirmed, refuted or unproven.
        fix_object: The single object carrying the fault, named exactly, for
            example "ConfigMap demo/checkout-config" or "Service demo/payments".
        fix_locator: The field, key or line inside that object, and the value
            found there — for example "key default.conf, line 3:
            wroker_connections 1024;" or "spec.ports[0].targetPort: 8081".
            A coordinate and an observation, nothing else. Never the corrected
            value, a replacement config, a command, or what will happen after a
            change: you cannot run the parser or the rollout that would prove any
            of it, and a confident guess here is the one part of this report an
            operator acts on directly.
        dismissed: Plausible causes ruled out, each with the reason.
    """
    _ = (
        symptom,
        root_cause,
        evidence,
        critic_ruling,
        fix_object,
        fix_locator,
        dismissed,
    )
    # The arguments are the report. Returning a receipt keeps the transcript
    # small; the caller reads the filed arguments from the run stream.
    return "Report filed. Stop here; do not repeat it in prose."


FILE_REPORT_TOOL = file_incident_report
