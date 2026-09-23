"""End-to-end MCP check against a live cluster and a live model.

Skipped by default: it needs a reachable cluster, a minted credential and a model
API key, and it costs several minutes and real tokens. It exercises exactly the
path an MCP client takes, so a green run here means the integration surface
works and not merely that the tools list.

    E2E=src/swarmr_kube/tests/test_e2e.py
    INCIDENT_E2E=1 .venv/bin/python -m pytest "$E2E" -s
    .venv/bin/python "$E2E" k8s_incident "will not start"
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
import time

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

POLL_SECONDS = 15
TIMEOUT_SECONDS = 900
_JOB = re.compile(r"job ([0-9a-f]{6,})")
_MILESTONE = re.compile(r"milestone=(\d+)")
_CURSOR = re.compile(r"since_cursor=(\d+)")

DEFAULT_REQUEST = (
    "Pods in namespace demo will not start and the ingress returns an error. "
    "Find the root cause."
)


def _text(result: object) -> str:
    content = getattr(result, "content", [])
    return getattr(content[0], "text", "") if content else ""


async def investigate(team: str, request: str, verbose: bool = True) -> str:
    """Start a job over MCP, follow its trail, return the final payload."""
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "swarmr.server"]
    )
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        started = _text(await session.call_tool(f"start_{team}", {"request": request}))
        if verbose:
            print(started, flush=True)
        match = _JOB.search(started)
        assert match, "the start tool returned no job id"
        job = match.group(1)

        milestone = cursor = 0
        deadline = time.monotonic() + TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            body = _text(
                await session.call_tool(
                    "check_task",
                    {
                        "job": job,
                        "wait_seconds": POLL_SECONDS,
                        "since_milestone": milestone,
                        "since_cursor": cursor,
                    },
                )
            )
            if verbose:
                print(body, flush=True)
            if found := _MILESTONE.search(body):
                milestone = int(found.group(1))
            if found := _CURSOR.search(body):
                cursor = int(found.group(1))
            if "\nREPORT\n" in body or "\nERROR " in body:
                return body
        raise AssertionError("timed out waiting for the investigation")


@pytest.mark.e2e
@pytest.mark.skipif(
    os.environ.get("INCIDENT_E2E") != "1",
    reason="needs a live cluster and a model API key; set INCIDENT_E2E=1",
)
def test_investigation_reports_a_root_cause() -> None:
    body = asyncio.run(investigate("k8s_incident", DEFAULT_REQUEST, verbose=True))
    assert "\nREPORT\n" in body, "the run settled without a report"
    assert "ROOT CAUSE" in body
    assert "no final report" not in body
    # Every specialist must be heard from, including the adjudicator.
    assert "critic" in body


def main() -> int:
    argv = sys.argv[1:]
    team = argv[0] if argv else "k8s_incident"
    request = " ".join(argv[1:]) or DEFAULT_REQUEST
    body = asyncio.run(investigate(team, request))
    return 0 if "\nREPORT\n" in body else 1


if __name__ == "__main__":
    raise SystemExit(main())
