"""Assembly of the Kubernetes incident team.

Stock Deep Agents: one `create_deep_agent` commander plus five `SubAgent`
specialists reached through the built-in `task` tool. Findings return as the
task result; the shared filesystem carries only bulk evidence.

Nothing about the target cluster is hardcoded. `discovery` profiles the live
cluster at build time and the profile is injected into every prompt, so the same
code runs against any cluster.
"""

from __future__ import annotations

from deepagents import FilesystemPermission, SubAgent, create_deep_agent
from langchain_openai import ChatOpenAI
from swarmr.core.attribution import Attribution
from swarmr.core.middleware import AnnounceName, FirstRoundBriefing
from swarmr.core.model import build_model
from swarmr.core.team import RunContext, TeamBuild

from swarmr_kube import prompts
from swarmr_kube.discovery import (
    ClusterProfile,
    profile_cluster,
    render_facts,
    render_routing,
)
from swarmr_kube.report_tool import FILE_REPORT_TOOL
from swarmr_kube.tools import (
    CRITIC_TOOLS,
    INVESTIGATOR_TOOLS,
    PLATFORM_TOOLS,
)

__all__ = ["build", "profile_target"]

# Rules are first-match-wins, and a subagent that omits `permissions` inherits
# the parent's, so every role states its own. Paths are absolute in the agent's
# virtual filesystem.
_NO_WRITES = [FilesystemPermission(operations=["write"], paths=["/**"], mode="deny")]

# Investigators may write only their evidence file. Anything else is scratch
# nobody reads, and it clutters the delegation trail.
_EVIDENCE_ONLY = [
    FilesystemPermission(
        operations=["write"], paths=["/evidence/**", "/**/evidence/**"], mode="allow"
    ),
    FilesystemPermission(operations=["write"], paths=["/**"], mode="deny"),
]


def _subagents(
    model: ChatOpenAI, facts: str, routing: str, attribution: Attribution
) -> list[SubAgent]:
    """The five specialists.

    Each `description` is what the commander reads when routing, so it names the
    symptoms the specialist handles rather than merely its subject area.
    """
    return [
        {
            "name": "workload",
            "description": (
                "Investigates whether the workload itself is failing: pod phase, "
                "container exit codes and reasons, restart counts, image pull "
                "results, container logs including the previous instance, declared "
                "probe config versus containerPort, and the pod -> replicaset -> "
                "deployment owner chain. Use for crash loops, restarts, unready "
                "containers, ImagePullBackOff, and 'is the app broken' questions."
            ),
            "system_prompt": prompts.workload(facts, routing),
            "middleware": [AnnounceName("workload", attribution)],
            "tools": INVESTIGATOR_TOOLS,
            "model": model,
            "permissions": _EVIDENCE_ONLY,
        },
        {
            "name": "network",
            "description": (
                "Investigates whether traffic can reach a serving backend: Service "
                "selector, port and targetPort, EndpointSlice readiness, Ingress and "
                "controller CRD routes, cluster DNS and load-balancer pods. Use for "
                "502, 503, connection refused, DNS failures and empty endpoints."
            ),
            "system_prompt": prompts.network(facts, routing),
            "middleware": [AnnounceName("network", attribution)],
            "tools": INVESTIGATOR_TOOLS,
            "model": model,
            "permissions": _EVIDENCE_ONLY,
        },
        {
            "name": "storage",
            "description": (
                "Investigates volume problems: PVC and PV binding, StorageClass and "
                "provisioner, FailedMount and FailedAttachVolume events, CSI driver "
                "controller and per-node plugin logs. Use for pods stuck in "
                "ContainerCreating or Pending on a volume."
            ),
            "system_prompt": prompts.storage(facts, routing),
            "middleware": [AnnounceName("storage", attribution)],
            "tools": INVESTIGATOR_TOOLS,
            "model": model,
            "permissions": _EVIDENCE_ONLY,
        },
        {
            "name": "platform",
            "description": (
                "Investigates node fitness and placement: node conditions, taints, "
                "kubernetes.io/arch, scheduling decisions and nodeSelectors, requests "
                "versus allocatable, live usage, FailedScheduling. Owns image "
                "architecture mismatch and proves it by reading the image's real "
                "registry manifest with image_platforms. Use for 'exec format error', "
                "StartError, platform-related pull failures, pods failing on some "
                "nodes but not others, Pending, and capacity or OOM questions."
            ),
            "system_prompt": prompts.platform(facts, routing),
            "middleware": [AnnounceName("platform", attribution)],
            "tools": PLATFORM_TOOLS,
            "model": model,
            "permissions": _EVIDENCE_ONLY,
        },
        {
            "name": "critic",
            "description": (
                "Adjudicates a finished root-cause hypothesis by trying to disprove it "
                "with independent tool calls. Send ONLY the symptom and hypothesis, "
                "never the reasoning or the investigators' reports. Returns RULING: "
                "confirmed | refuted | unproven. Must be the last step of every "
                "investigation."
            ),
            "system_prompt": prompts.critic(facts, routing),
            "middleware": [AnnounceName("critic", attribution)],
            "tools": CRITIC_TOOLS,
            "model": model,
            # The critic reports a ruling; it has nothing to persist.
            "permissions": _NO_WRITES,
        },
    ]


def _banner(profile: ClusterProfile) -> str:
    """One line naming the cluster this run is looking at."""
    return (
        f"{profile.node_count} nodes ({'/'.join(profile.architectures)}), "
        f"ingress={profile.controller or 'none'}, "
        f"k8s={profile.version.split(' ')[0]}"
    )


def profile_target() -> str:
    """Describe the live cluster without building an agent.

    Separate from `build` because building constructs a model client: fused, an
    operator asking "which cluster am I pointed at" got a missing-API-key error,
    having never contacted the cluster at all.
    """
    return _banner(profile_cluster())


def build(run: RunContext) -> TeamBuild:
    """Profile the live cluster, then build the team around what is actually there."""
    model = build_model()
    profile = profile_cluster()
    facts = render_facts(profile)
    routing = render_routing(profile)

    graph = create_deep_agent(
        model=model,
        # The commander holds no cluster tools on purpose: its context stays
        # clean, and it cannot fabricate an observation it never received. The
        # one tool it does hold files the final report.
        tools=[FILE_REPORT_TOOL],
        system_prompt=prompts.commander(facts, routing),
        subagents=_subagents(model, facts, routing, run.attribution),
        # Planning belongs in write_todos, which the harness already provides.
        # Left free, the commander writes a scratch plan to /tmp instead, which
        # is invisible to the caller and pure noise in the delegation trail.
        # Investigators keep their own write access for evidence/ files.
        permissions=_NO_WRITES,
        # The first briefing of each specialist is normalised by the harness, so
        # the commander cannot pre-frame a domain it has not looked at yet. The
        # critic is exempt: its payload is a finished hypothesis.
        middleware=[FirstRoundBriefing(exempt=("critic",))],
    )
    return TeamBuild(graph=graph, banner=_banner(profile))
