"""Reading an OCI registry over plain HTTP.

One responsibility: asking a container registry what an image really is. This is
the only tool that leaves the cluster, and it speaks the distribution API rather
than the Kubernetes API, so it shares nothing with `tools.py` except the output
wrappers. Keeping it separate also keeps its reference parser — the part that
has actually been wrong — testable without a cluster.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from langchain_core.tools import tool

from swarmr_kube.output import cached, emit, guard

__all__ = ["image_platforms", "parse_ref"]

_REGISTRIES: dict[str, tuple[str, str | None]] = {
    "docker.io": (
        "registry-1.docker.io",
        "https://auth.docker.io/token?service=registry.docker.io"
        "&scope=repository:{repo}:pull",
    ),
    "ghcr.io": (
        "ghcr.io",
        "https://ghcr.io/token?service=ghcr.io&scope=repository:{repo}:pull",
    ),
    "quay.io": ("quay.io", None),
    "registry.k8s.io": ("registry.k8s.io", None),
}
_MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


def parse_ref(image: str) -> tuple[str, str, str]:
    """Split an image reference into (registry, repository, tag-or-digest)."""
    ref, _, digest_part = image.partition("@")
    head, slash, tail = ref.partition("/")
    # A leading segment is a registry only when a path follows it. Without the
    # slash test, "nginx:1.29" parses as host "nginx" and port "1.29".
    if slash and ("." in head or ":" in head or head == "localhost"):
        registry, remainder = head, tail
    else:
        registry, remainder = "docker.io", ref
    repo, _, tag = remainder.rpartition(":")
    if not repo or "/" in tag:
        repo, tag = remainder, "latest"
    if registry == "docker.io" and "/" not in repo:
        repo = f"library/{repo}"
    return registry, repo, digest_part or tag


def _fetch_json(url: str, headers: dict[str, str]) -> dict[str, Any]:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read())


@tool(parse_docstring=True)
@guard
@cached
def image_platforms(image: str) -> str:
    """List the OS/architecture platforms a container image actually supports.

    Queries the registry manifest directly: read-only, no docker daemon. Use it
    to prove or disprove an architecture mismatch by comparing the result
    against the node's kubernetes.io/arch label. An "exec format error" or a
    platform-related pull failure is a symptom; this tool is the proof.

    Args:
        image: Image reference as it appears in the pod spec, e.g. "nginx:1.29"
            or "ghcr.io/org/app@sha256:...".
    """
    registry, repo, reference = parse_ref(image)
    host, token_url = _REGISTRIES.get(registry, (registry, None))
    headers = {"Accept": _MANIFEST_ACCEPT}
    if token_url:
        try:
            token = _fetch_json(token_url.format(repo=repo), {})
            headers["Authorization"] = f"Bearer {token['token']}"
        except (urllib.error.URLError, KeyError, OSError) as exc:
            return f"registry auth failed for {registry}/{repo}: {exc}"

    try:
        manifest = _fetch_json(f"https://{host}/v2/{repo}/manifests/{reference}", headers)
    except urllib.error.HTTPError as exc:
        return f"registry lookup failed: HTTP {exc.code} for {image}"
    except (urllib.error.URLError, OSError) as exc:
        return f"registry unreachable: {exc}"

    if "manifests" in manifest:
        platforms = sorted(
            f"{p.get('os')}/{p.get('architecture')}"
            + (f"/{p['variant']}" if p.get("variant") else "")
            for m in manifest["manifests"]
            if (p := m.get("platform")) and p.get("architecture") != "unknown"
        )
        return emit({"image": image, "multi_arch": True, "platforms": platforms})

    single = "unknown"
    if config_digest := manifest.get("config", {}).get("digest"):
        try:
            blob = _fetch_json(
                f"https://{host}/v2/{repo}/blobs/{config_digest}",
                {**headers, "Accept": "application/json"},
            )
            single = f"{blob.get('os')}/{blob.get('architecture')}"
        except (urllib.error.URLError, urllib.error.HTTPError, OSError):
            pass
    return emit({"image": image, "multi_arch": False, "platforms": [single]})
