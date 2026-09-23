"""What this team promises the shared machinery, and its own guardrails.

`core` renders and records without knowing any role name, so the team must
declare its own vocabulary. Filesystem permissions are the other half of the
read-only guarantee: prompts ask, permissions enforce.
"""

from __future__ import annotations

import subprocess
import sys

from swarmr.core.team import Lazy
from swarmr.teams import get
from swarmr.teams import names as registered_names

from swarmr_kube import TEAM
from swarmr_kube.agent import _EVIDENCE_ONLY, _NO_WRITES
from swarmr_kube.digest import digest_result
from swarmr_kube.tools import CRITIC_TOOLS, PLATFORM_TOOLS


class TestVocabulary:
    def test_team_declares_every_name_core_uses(self) -> None:
        assert TEAM.orchestrator == "commander"
        assert TEAM.audit_agents == ("critic",)
        assert TEAM.report_tool == "file_incident_report"
        assert TEAM.digest is digest_result

    def test_roster_names_the_specialists(self) -> None:
        names = {member.name for member in TEAM.members}
        assert names >= {
            "commander",
            "workload",
            "network",
            "storage",
            "platform",
            "critic",
        }
        assert TEAM.roster().count("\n") == len(TEAM.members) - 1

    def test_registry_exposes_the_team(self) -> None:
        assert get(TEAM.name) is TEAM
        assert TEAM.name in registered_names()

    def test_the_heavyweight_fields_are_declared_lazily(self) -> None:
        """Importing this team must not import its agent stack.

        `teams --list` and the MCP server read `name`, `summary` and
        `description` from every installed team on every start. Bind `build`,
        `profile` or `render_report` directly and that listing pulls in
        deepagents, the model SDK and the Kubernetes client — 4533 modules
        instead of 133 — which is a regression no other test would notice.
        """
        for name in ("build", "profile", "render_report"):
            declared = getattr(TEAM, name)
            assert isinstance(declared, Lazy), name
            assert declared.target.startswith("swarmr_kube.")


class TestToolSets:
    def test_no_tool_can_mutate_the_cluster(self) -> None:
        """Phase one is read-only in code as well as by credential."""
        every = {tool.name for tool in CRITIC_TOOLS + PLATFORM_TOOLS}
        assert not {"k_apply", "k_delete", "k_patch", "k_exec"} & every


class TestPermissions:
    """These pin our own configuration, not upstream's evaluator.

    An earlier version called `deepagents.middleware.filesystem`'s private
    `_check_fs_permission`, which breaks on any upgrade of a dependency we do
    not control. What this team is answerable for is the rule sets it declares:
    what they grant, what they deny, and in which order.
    """

    def test_orchestrator_and_critic_grant_no_write_anywhere(self) -> None:
        """The plan belongs in write_todos; a scratch file in /tmp helps nobody."""
        assert [(r.operations, r.paths, r.mode) for r in _NO_WRITES] == [
            (["write"], ["/**"], "deny")
        ]

    def test_investigators_allow_evidence_before_the_catch_all_deny(self) -> None:
        """Rules are first-match-wins, so the order is the policy: a leading
        deny on /** would silence the allow and no evidence could be written."""
        assert [r.mode for r in _EVIDENCE_ONLY] == ["allow", "deny"]
        assert _EVIDENCE_ONLY[0].paths == ["/evidence/**", "/**/evidence/**"]
        assert _EVIDENCE_ONLY[1].paths == ["/**"]
        assert all(rule.operations == ["write"] for rule in _EVIDENCE_ONLY)


def test_publishing_the_mcp_surface_imports_no_team_implementation() -> None:
    """The startup cost claim, measured where it is made.

    Core cannot make this assertion: it ships no team, so there is nothing for
    it to prove unimported. The claim only has content where an installed team
    exists, which is here. A subprocess because this process has already
    imported the agent module for other tests, and the point is what a fresh
    server loads.
    """
    probe = (
        "import sys\n"
        "from swarmr.server import build_server\n"
        "build_server()\n"
        "heavy = [m for m in sys.modules if m.endswith('swarmr_kube.agent')]\n"
        "print(heavy, len(sys.modules))\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    loaded, _, count = done.stdout.strip().rpartition(" ")
    assert loaded == "[]", done.stdout
    # Guards the order of magnitude, not a number to chase: the whole agent
    # stack is ~4500 modules, and a listing that stays under a thousand cannot
    # have loaded it.
    assert int(count) < 1500, done.stdout
