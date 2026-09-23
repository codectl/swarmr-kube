"""What must never survive into a delivered report.

One responsibility: suppression policy. The team reads cluster state, so it can
observe a fault but cannot validate a correction — it cannot run the parser or
the rollout that would prove one. Four prompt attempts failed to stop the model
prescribing anyway: told to verify, it certified; told to withhold, it
certified; told to point rather than prescribe, it prescribed. So the policy is
enforced in code, on the render path, and the caveats are not the model's to
phrase.

The render path is the only place this can live: the filed report is emitted
from the tool call arguments before the tool body runs, so nothing the tool
itself does can protect what the caller receives.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["LOCATION_CAVEAT", "OMITTED_NOTE", "diagnosis", "locator", "one_line"]

# Printed by the template, never by the model.
LOCATION_CAVEAT = (
    "  Location only. This team reads cluster state, so it cannot check that any "
    "edit is accepted by the application: decide the change yourself and validate "
    "it before rolling out."
)

OMITTED_NOTE = (
    "  One sentence omitted: it named the value that would be correct, which this "
    "team cannot validate — a live run named one that was itself invalid, so "
    "acting on it would have reproduced the outage. The observed fault is in "
    "EVIDENCE and WHERE TO FIX IT."
)

# A locator is a coordinate and an observation. These markers are what a
# prescription is made of: an instruction to change something, or a claim about
# what happens afterwards. Clipping one only shortens it, so a locator carrying
# them is dropped and the object kept.
_PRESCRIPTIVE = re.compile(
    r"\b(replace|rename|change|set|edit|update|correct|fix|remove|delete|add|"
    r"apply|restart|roll ?out|recreate|patch|should|must|instead|will)\b",
    re.IGNORECASE,
)

# "X instead of Y", "Y should be", "expected Y": Y is the value that would be
# correct, which is a judgement, not a reading. A live run put "instead of
# worker_connections" in the root cause - invalid in that container's config
# context, so acting on it reproduces the outage - and the locator guard does not
# cover the diagnosis. No membership test can vet Y: a string appearing in
# evidence proves occurrence, not correctness, and "80" is a substring of "8080".
# Two earlier versions excised the clause and mangled real sentences, so the
# finding is left exactly as filed and the claim is labelled wherever it occurs.
# "typo for X" and "misspelling of X" name X exactly as "instead of X" does, and
# a live commander dispatch used that wording verbatim, so a naming-only marker
# set is not enough: what matters is that a value is offered as the right one.
_COUNTERFACTUAL = re.compile(
    r"\b(?:instead of|rather than|should (?:be|read|have)|expected|"
    r"(?:typo|misspelling|misspelt|misspelled|shorthand)\s+(?:for|of)|"
    r"correct(?:ly)?\s+spell\w*)\b",
    re.IGNORECASE,
)
_SENTENCE = re.compile(r"(?<=[.;])\s+")


def one_line(value: Any, limit: int = 120) -> str:
    """Collapse to a single clipped line: a locator, with no room for a recipe.

    Public because the report renders two located fields with it, and only one
    of them is subject to the prescription check.
    """
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def locator(value: Any) -> str:
    """One line naming where the fault is, or "" when it prescribes a fix instead.

    Dropped whole rather than clipped: a prescription with its verb removed is
    still a prescription, and the object it points at is reported separately.
    """
    text = one_line(value)
    return "" if text and _PRESCRIPTIVE.search(text) else text


def diagnosis(root_cause: str) -> tuple[str, bool]:
    """The chain, minus any sentence naming a value that would be correct.

    Returns the kept text and whether anything was dropped, so the caller can
    label the gap instead of silently shortening the finding.

    Sentence granularity on purpose: two earlier versions cut the clause out of
    the sentence and left mangled punctuation or swallowed the trailing half.
    Nothing is rewritten — a sentence is kept whole or dropped whole.
    """
    kept = [s for s in _SENTENCE.split(root_cause) if not _COUNTERFACTUAL.search(s)]
    joined = " ".join(part.strip() for part in kept if part.strip())
    return joined, len(kept) != len(_SENTENCE.split(root_cause))
