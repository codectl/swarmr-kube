"""Reading an image reference the way a registry does, and who may ask.

The parser is the part that has actually been wrong in production, and the
lookup is scoped to the two roles that make or check an architecture claim.
"""

from __future__ import annotations

import pytest

from swarmr_kube.registry import parse_ref
from swarmr_kube.tools import (
    CRITIC_TOOLS,
    INVESTIGATOR_TOOLS,
    PLATFORM_TOOLS,
)


@pytest.mark.parametrize(
    ("image", "expected"),
    [
        # "nginx:1.29" once parsed as host "nginx" with port "1.29".
        ("nginx:1.29", ("docker.io", "library/nginx", "1.29")),
        ("amd64/nginx:1.29", ("docker.io", "amd64/nginx", "1.29")),
        ("ghcr.io/org/app:v1", ("ghcr.io", "org/app", "v1")),
        ("registry.k8s.io/pause:3.9", ("registry.k8s.io", "pause", "3.9")),
        ("nginx", ("docker.io", "library/nginx", "latest")),
    ],
)
def test_reference_parsing(image: str, expected: tuple[str, str, str]) -> None:
    """A registry is only a registry when a path follows it."""
    assert parse_ref(image) == expected


def test_digest_reference_is_preserved() -> None:
    registry, repo, reference = parse_ref("ghcr.io/org/app@sha256:abc123")
    assert (registry, repo) == ("ghcr.io", "org/app")
    assert reference == "sha256:abc123"


def test_only_platform_and_critic_can_prove_architecture() -> None:
    """A symptom is not proof; the registry lookup is, so it is scoped."""
    assert "image_platforms" not in {tool.name for tool in INVESTIGATOR_TOOLS}
    assert "image_platforms" in {tool.name for tool in PLATFORM_TOOLS}
    assert "image_platforms" in {tool.name for tool in CRITIC_TOOLS}
