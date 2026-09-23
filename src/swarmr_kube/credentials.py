"""Minting the read-only credential this team runs on.

One responsibility: producing a kubeconfig that can only read. The team refuses
to use your ambient kubeconfig, because on most clusters the default context is
cluster-admin, so this module mints a short-lived token for the least-privilege
ServiceAccount and writes a kubeconfig containing nothing else.

Everything goes through the Kubernetes API rather than `kubectl`. The rules
themselves live in `rbac.py`; the command line lives in `credentials_cli.py`.

Multi-cluster is first class: each context gets its own credential file, so an
on-prem k3s and an AKS cluster can be configured side by side.
"""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from kubernetes import client, config

from swarmr_kube.rbac import SA_NAME, SA_NAMESPACE, ensure_rbac

__all__ = ["DEFAULT_TTL", "Minted", "contexts", "credential_path", "mint"]

DEFAULT_TTL = "8h"
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _repo_root() -> Path:
    """Repository root, found by walking up to the directory holding pyproject.toml."""
    for parent in Path(__file__).resolve().parents:
        if (parent / "pyproject.toml").is_file():
            return parent
    return Path.cwd()


def credential_path(context: str | None, directory: Path | None = None) -> Path:
    """Where a context's credential lives.

    One file per context, because a single file cannot serve two clusters and
    silently pointing an investigation at the wrong cluster is the worst
    possible failure mode.
    """
    base = directory or _repo_root()
    if not context:
        return base / ".incident-reader.kubeconfig"
    return base / f".incident-reader.{_SAFE.sub('-', context)}.kubeconfig"


@dataclass(frozen=True, slots=True)
class Minted:
    context: str
    server: str
    path: Path
    can_read: bool
    can_write: bool

    @property
    def ok(self) -> bool:
        return self.can_read and not self.can_write


def _kubeconfig_document_path() -> Path:
    """The kubeconfig to read, honouring KUBECONFIG's first entry."""
    if env := os.environ.get("KUBECONFIG"):
        first = env.split(os.pathsep)[0]
        if first:
            return Path(first).expanduser()
    return Path(config.kube_config.KUBE_CONFIG_DEFAULT_LOCATION).expanduser()


def _load_kubeconfig() -> dict[str, Any]:
    return yaml.safe_load(_kubeconfig_document_path().read_text()) or {}


def contexts() -> tuple[list[str], str | None]:
    """Available kubeconfig contexts and the active one."""
    document = _load_kubeconfig()
    names = [
        str(entry.get("name"))
        for entry in document.get("contexts") or []
        if entry.get("name")
    ]
    return names, document.get("current-context")


def _cluster_details(context: str | None) -> tuple[str, str]:
    """Server URL and base64 CA bundle for a context.

    Reads the kubeconfig directly rather than through the client's private
    loader: the loader exposes no public accessor for a cluster, and reaching
    into it breaks on any upstream refactor. A kubeconfig may carry the CA
    inline or as a file path; the minted config always embeds it, so the result
    is portable and self-contained.
    """
    document = _load_kubeconfig()
    wanted = context or document.get("current-context")
    cluster_name = next(
        (
            (entry.get("context") or {}).get("cluster")
            for entry in document.get("contexts") or []
            if entry.get("name") == wanted
        ),
        None,
    )
    if not cluster_name:
        raise RuntimeError(f"context {wanted!r} not found in the kubeconfig")

    cluster = next(
        (
            entry.get("cluster") or {}
            for entry in document.get("clusters") or []
            if entry.get("name") == cluster_name
        ),
        None,
    )
    if not cluster:
        raise RuntimeError(f"cluster {cluster_name!r} not found in the kubeconfig")

    server = str(cluster.get("server", ""))
    if data := cluster.get("certificate-authority-data"):
        return server, str(data)
    if path := cluster.get("certificate-authority"):
        return server, base64.b64encode(
            Path(str(path)).expanduser().read_bytes()
        ).decode()
    return server, ""


def _mint_token(api: Any, ttl_seconds: int) -> str:
    """Request a bound, expiring token via the TokenRequest API."""
    request = client.AuthenticationV1TokenRequest(
        spec=client.V1TokenRequestSpec(audiences=[], expiration_seconds=ttl_seconds)
    )
    created: Any = client.CoreV1Api(api).create_namespaced_service_account_token(
        SA_NAME, SA_NAMESPACE, request
    )
    return str(created.status.token)


def _kubeconfig_document(server: str, ca: str, token: str) -> dict[str, Any]:
    cluster: dict[str, Any] = {"server": server}
    if ca:
        cluster["certificate-authority-data"] = ca
    else:
        # No CA available: refuse to silently disable verification.
        raise RuntimeError(
            "the source context has no certificate authority; refusing to write a "
            "kubeconfig that cannot verify the API server"
        )
    return {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"name": "incident", "cluster": cluster}],
        "contexts": [
            {
                "name": "incident",
                "context": {"cluster": "incident", "user": SA_NAME},
            }
        ],
        "current-context": "incident",
        "users": [{"name": SA_NAME, "user": {"token": token}}],
    }


def _can(api: Any, verb: str, resource: str) -> bool:
    """Ask the API server itself whether this credential may do something."""
    review = client.V1SelfSubjectAccessReview(
        spec=client.V1SelfSubjectAccessReviewSpec(
            resource_attributes=client.V1ResourceAttributes(verb=verb, resource=resource)
        )
    )
    result: Any = client.AuthorizationV1Api(api).create_self_subject_access_review(review)
    return bool(result.status and result.status.allowed)


def _seconds(ttl: str) -> int:
    unit = ttl[-1].lower()
    factor = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(unit)
    if factor is None:
        raise ValueError(f"unsupported ttl {ttl!r}; use e.g. 30m, 8h, 2d")
    return int(ttl[:-1]) * factor


def mint(
    context: str | None = None,
    ttl: str = DEFAULT_TTL,
    directory: Path | None = None,
) -> Minted:
    """Create the RBAC, mint a token, write the kubeconfig, verify it.

    Uses your admin credentials for the chosen context to do the setup; the
    written file contains only the ServiceAccount token.
    """
    config.load_kube_config(context=context)
    admin = client.ApiClient()
    ensure_rbac(admin)
    token = _mint_token(admin, _seconds(ttl))

    server, ca = _cluster_details(context)
    document = _kubeconfig_document(server, ca, token)

    target = credential_path(context, directory)
    target.write_text(yaml.safe_dump(document, sort_keys=False))
    target.chmod(0o600)

    # Verify with the minted credential, not the admin one: the guarantee is
    # about what this file can do.
    reader = client.ApiClient(
        config.new_client_from_config(config_file=str(target)).configuration
    )
    return Minted(
        context=context or "(current)",
        server=server,
        path=target,
        can_read=_can(reader, "list", "pods"),
        can_write=_can(reader, "delete", "pods"),
    )
