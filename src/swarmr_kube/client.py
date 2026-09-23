"""Which credential this team connects with, and the API clients built on it.

One responsibility: getting an authenticated connection, and failing closed when
the only credential available is not the least-privilege one. Result shaping
lives in `output.py`, kind normalisation in `kinds.py`, and the diagnostic tools
themselves in `tools.py`.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from functools import cache
from pathlib import Path
from typing import Any

import yaml
from kubernetes import client, config
from kubernetes.dynamic import DynamicClient
from swarmr.core.team import TeamError

__all__ = [
    "CredentialError",
    "core_api",
    "custom_api",
    "dynamic_api",
    "kube_clients",
]


class CredentialError(TeamError):
    """Raised when no usable least-privilege credential is available.

    A `TeamError`, so both surfaces print the sentence instead of a traceback:
    an expired token is a normal event on an 8h credential, not a crash.
    """


CREDENTIAL_GLOB = ".incident-reader*.kubeconfig"
_MINT_COMMAND = "incident-credentials --context <name>"
_MINTED_PREFIX = ".incident-reader."
_MINTED_SUFFIX = ".kubeconfig"
# Refresh slightly before expiry rather than exactly at it: an investigation
# runs for minutes, and a token with seconds left would die mid-flight, halfway
# through a delegation, which is the one failure this is meant to remove.
_REFRESH_MARGIN = timedelta(minutes=5)
# Module-level so a test can point it somewhere absent without patching
# Path.exists process-wide, which would silently affect every other lookup.
IN_CLUSTER_TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")


def _minted_context(origin: str) -> str | None:
    """The context a minted credential belongs to, or None if we did not mint it.

    The gate on automatic refresh: a file this team wrote is ours to replace,
    and any other kubeconfig — an operator's own, pointed at by
    INCIDENT_KUBECONFIG — is not.
    """
    name = Path(origin).name
    if name.startswith(_MINTED_PREFIX) and name.endswith(_MINTED_SUFFIX):
        return name[len(_MINTED_PREFIX) : -len(_MINTED_SUFFIX)] or None
    return None


def _remint_command(origin: str) -> str:
    """The exact command that replaces this credential.

    Minted files carry their context in the name, so the remedy can name it
    instead of leaving the operator to substitute a placeholder.
    """
    context = _minted_context(origin)
    return f"incident-credentials --context {context}" if context else _MINT_COMMAND


def _token_expiry(token: str) -> datetime | None:
    """The `exp` claim of a service-account JWT, or None if there is not one.

    Read, never verified: the API server is the only thing entitled to validate
    this token. All that is wanted here is the expiry the issuer already
    published, so a dead credential can be reported before a request is sent.
    An opaque or malformed token simply has no expiry to read, and the 401 path
    below covers it.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload))
        return datetime.fromtimestamp(float(claims["exp"]), UTC)
    except (ValueError, KeyError, TypeError, binascii.Error):
        return None


def _soonest_expiry(path: str) -> datetime | None:
    """When this credential stops working, as far as its tokens admit.

    None means nothing readable said — an opaque token, or a kubeconfig with no
    inline token at all. Those are left to the cluster and the 401 path.
    """
    try:
        loaded = yaml.safe_load(Path(path).read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise CredentialError(f"cannot read credential {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise CredentialError(f"credential {path} is not a kubeconfig")

    expiries = [
        expiry
        for user in loaded.get("users") or []
        if isinstance(token := ((user or {}).get("user") or {}).get("token"), str)
        if (expiry := _token_expiry(token)) is not None
    ]
    return min(expiries) if expiries else None


def _refresh(path: str, context: str) -> None:
    """Mint a new token into the same file, using your admin credentials.

    Imported here rather than at module scope: minting is an operator action
    that reads the ambient kubeconfig, and the tool surface must not carry that
    machinery just to make a read.

    Fails closed. If the refreshed credential can do anything beyond reading,
    it is not the credential this team is allowed to investigate with, and the
    run stops instead of quietly escalating.
    """
    from swarmr_kube.credentials import mint

    minted = mint(context=context, directory=Path(path).parent)
    if not minted.ok:
        raise CredentialError(
            f"refreshed credential for {context!r} is not read-only "
            f"(read={minted.can_read}, write={minted.can_write}). Refusing to "
            "investigate with it."
        )
    print(
        f"credential {Path(path).name} had expired; minted a fresh read-only "
        f"token for context {context!r}.",
        file=sys.stderr,
    )


def _ensure_live(path: str) -> str:
    """Return `path`, refreshing the credential first if it is spent.

    An 8h token expires every working day, so the previous behaviour — a 401
    raised sixty frames deep in the generated client — was a daily event. The
    expiry is in the token this team minted itself, so it is knowable offline,
    before a single request, and fixable by the same code path the CLI uses.

    Refresh is limited to files this team minted, one per context, so it works
    the same with one cluster or twenty: whichever credential the resolution
    order selected is the one refreshed. Ambiguity is settled before this point
    and is still an error, because refreshing every candidate would be picking
    a cluster to investigate.

    A credential we did not mint, or a refresh that cannot be done here, falls
    back to naming the exact command to run.
    """
    expiry = _soonest_expiry(path)
    if expiry is None or expiry - _REFRESH_MARGIN > datetime.now(UTC):
        return path

    spent = (
        f"expired {_ago(datetime.now(UTC) - expiry)}"
        if expiry <= datetime.now(UTC)
        else f"expires at {expiry.astimezone().isoformat(timespec='seconds')}"
    )
    context = _minted_context(path)
    if context is None or os.environ.get("INCIDENT_NO_REFRESH"):
        raise CredentialError(
            f"credential {Path(path).name} {spent}. Run "
            f"`{_remint_command(path)}` to mint a fresh read-only token."
        )
    try:
        _refresh(path, context)
    except CredentialError:
        raise
    except Exception as exc:
        raise CredentialError(
            f"credential {Path(path).name} {spent}, and minting a new one for "
            f"context {context!r} failed: {type(exc).__name__}: {exc}. Your own "
            f"kubeconfig needs that context and the rights to create the "
            f"incident-reader RBAC; run `{_remint_command(path)}` to see the "
            "full error."
        ) from exc
    return path


def _ago(age: timedelta) -> str:
    """A duration an operator reads at a glance."""
    hours, seconds = divmod(int(age.total_seconds()), 3600)
    if hours >= 24:
        return f"{hours // 24}d{hours % 24}h ago"
    return f"{hours}h{seconds // 60}m ago" if hours else f"{seconds // 60}m ago"


def _minted_credentials() -> list[Path]:
    """Every minted reader kubeconfig, nearest directory first.

    A search rather than a fixed parent depth: an installed package sits at a
    different depth than a source checkout, and hardcoding the count breaks
    silently the moment a directory moves.
    """
    seen: dict[Path, None] = {}
    for directory in (*Path(__file__).resolve().parents, Path.cwd()):
        for candidate in sorted(directory.glob(CREDENTIAL_GLOB)):
            if candidate.is_file():
                seen.setdefault(candidate.resolve(), None)
    return list(seen)


def _kubeconfig() -> str | None:
    """Resolve the credential, failing closed.

    Order:
      1. INCIDENT_KUBECONFIG, if set.
      2. INCIDENT_CONTEXT, naming a context that has been minted.
      3. Exactly one minted credential on disk.
      4. The in-cluster ServiceAccount, when running as a Pod (returns None).

    Deliberately NOT in that list: the ambient kubeconfig. On most clusters the
    default context is cluster-admin, so falling back to it would silently void
    the read-only guarantee. A missing credential is an error, not a reason to
    escalate privilege.

    Several minted credentials with no choice expressed is also an error. An
    investigation reported against the wrong cluster is worse than one that
    refuses to start.
    """
    if explicit := os.environ.get("INCIDENT_KUBECONFIG"):
        if not Path(explicit).exists():
            raise CredentialError(
                f"INCIDENT_KUBECONFIG points at a missing file: {explicit}"
            )
        return _ensure_live(explicit)

    minted = _minted_credentials()
    if wanted := os.environ.get("INCIDENT_CONTEXT"):
        suffix = f".incident-reader.{wanted}.kubeconfig"
        for candidate in minted:
            if candidate.name == suffix:
                return _ensure_live(str(candidate))
        raise CredentialError(
            f"no credential minted for context {wanted!r}. Run "
            f"`incident-credentials --context {wanted}` first."
        )

    if len(minted) == 1:
        return _ensure_live(str(minted[0]))
    if len(minted) > 1:
        names = ", ".join(p.name for p in minted)
        raise CredentialError(
            "several minted credentials found and no cluster chosen: "
            f"{names}. Set INCIDENT_CONTEXT to the context you mean, or "
            "INCIDENT_KUBECONFIG to an exact path. Refusing to guess which "
            "cluster to investigate."
        )

    if IN_CLUSTER_TOKEN.exists():
        return None
    raise CredentialError(
        f"no read-only credential found. Run `{_MINT_COMMAND}` to mint one for the "
        "incident-reader ServiceAccount, or set INCIDENT_KUBECONFIG to a kubeconfig "
        "with get/list/watch only. The ambient kubeconfig is never used: it is "
        "usually cluster-admin."
    )


class _AuthCheckedApiClient(client.ApiClient):
    """The one place every request passes through, so 401 is translated once.

    Each typed API — `CoreV1Api`, `CustomObjectsApi`, `DynamicClient` — funnels
    through `ApiClient.request`, so translating here covers every call the team
    makes today and every call added later, rather than each call site
    remembering to. `_ensure_live` already refreshes the common case offline;
    this covers the rest: a token revoked mid-run, a rotated in-cluster
    ServiceAccount, an operator-supplied kubeconfig with an opaque token whose
    expiry cannot be read ahead of time.

    Only 401 is claimed. 403 is a working credential doing its job — the
    read-only guarantee holding — and `output.guard` already explains it to the
    model as feedback rather than failure.
    """

    def __init__(self, origin: str) -> None:
        super().__init__()
        self._origin = origin

    def request(self, *args: Any, **kwargs: Any) -> Any:
        try:
            return super().request(*args, **kwargs)
        except client.ApiException as exc:
            if exc.status != 401:
                raise
            raise CredentialError(
                f"the cluster rejected {self._origin} as unauthorized (401). The "
                "token is expired or revoked; run "
                f"`{_remint_command(self._origin)}` to mint a fresh read-only "
                "token."
            ) from exc


@cache
def _api_client() -> Any:
    """One shared connection for every tool and for cluster discovery."""
    path = _kubeconfig()
    if path is None:
        config.load_incluster_config()
        return _AuthCheckedApiClient("the in-cluster ServiceAccount token")
    config.load_kube_config(config_file=path)
    return _AuthCheckedApiClient(path)


def kube_clients() -> tuple[Any, Any, Any, Any]:
    """Typed clients for discovery: (core, apps, storage, version)."""
    api = _api_client()
    return (
        client.CoreV1Api(api),
        client.AppsV1Api(api),
        client.StorageV1Api(api),
        client.VersionApi(api),
    )


@cache
def dynamic_api() -> Any:
    return DynamicClient(_api_client())


@cache
def core_api() -> Any:
    return client.CoreV1Api(_api_client())


@cache
def custom_api() -> Any:
    return client.CustomObjectsApi(_api_client())
