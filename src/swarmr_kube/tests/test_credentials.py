"""Credential policy: read-only by construction, and never the wrong cluster.

Two independent barriers protect a live cluster here — the tool surface only
reads, and the credential cannot write. These tests defend the second one, plus
the rule that an ambiguous cluster choice is an error rather than a guess.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from kubernetes import client

from swarmr_kube.client import (
    CredentialError,
    _ago,
    _AuthCheckedApiClient,
    _kubeconfig,
)
from swarmr_kube.credentials import credential_path
from swarmr_kube.rbac import READ_ONLY_RULES, manifest

_CLIENT = "swarmr_kube.client"
_MINTED = f"{_CLIENT}._minted_credentials"
_TOKEN = f"{_CLIENT}.IN_CLUSTER_TOKEN"
_CREDENTIALS = "swarmr_kube.credentials"


@dataclass(frozen=True, slots=True)
class _Minted:
    """What `credentials.mint` reports back, without a cluster to ask.

    Mirrors `Minted.ok`, because that is the property the refresh path gates
    on. Named the same deliberately: a stub that invents its own vocabulary
    hides a rename instead of failing on it.
    """

    can_read: bool
    can_write: bool

    @property
    def ok(self) -> bool:
        return self.can_read and not self.can_write


def test_rbac_rules_grant_no_write_verb() -> None:
    forbidden = {"create", "update", "patch", "delete", "deletecollection", "*"}
    for rule in READ_ONLY_RULES:
        assert not forbidden.intersection(rule["verbs"]), rule


def test_manifest_uses_kubernetes_key_casing() -> None:
    """The client model wants api_groups; Kubernetes YAML wants apiGroups."""
    rendered = manifest()
    assert "apiGroups" in rendered
    assert "api_groups" not in rendered


def test_manifest_covers_every_rule() -> None:
    rendered = manifest()
    for rule in READ_ONLY_RULES:
        for resource in rule["resources"]:
            assert resource in rendered


def test_credential_path_is_per_context() -> None:
    """One file per cluster: a single file cannot serve two clusters."""
    assert credential_path("my-aks", Path("/x")).name == (
        ".incident-reader.my-aks.kubeconfig"
    )
    assert credential_path(None, Path("/x")).name == ".incident-reader.kubeconfig"


def test_context_names_are_made_filesystem_safe() -> None:
    name = credential_path("arn:aws:eks:eu-west-1:123:cluster/prod", Path("/x")).name
    assert "/" not in name.removeprefix(".incident-reader.")


def test_missing_credential_fails_closed(monkeypatch: Any, tmp_path: Path) -> None:
    """The ambient kubeconfig is usually cluster-admin: never fall back to it.

    The absent in-cluster token is faked by repointing the module-level path,
    not by stubbing Path.exists, which would answer for every unrelated lookup
    in the process as well.
    """
    monkeypatch.delenv("INCIDENT_KUBECONFIG", raising=False)
    monkeypatch.delenv("INCIDENT_CONTEXT", raising=False)
    monkeypatch.setattr(_MINTED, lambda: [])
    monkeypatch.setattr(_TOKEN, tmp_path / "no-serviceaccount-token")
    with pytest.raises(CredentialError):
        _kubeconfig()


def test_in_cluster_token_is_used_when_present(monkeypatch: Any, tmp_path: Path) -> None:
    """Running as a Pod is the one case where no file is needed."""
    monkeypatch.delenv("INCIDENT_KUBECONFIG", raising=False)
    monkeypatch.delenv("INCIDENT_CONTEXT", raising=False)
    monkeypatch.setattr(_MINTED, lambda: [])
    token = tmp_path / "token"
    token.write_text("t")
    monkeypatch.setattr(_TOKEN, token)
    assert _kubeconfig() is None


def test_explicit_missing_path_is_an_error(monkeypatch: Any) -> None:
    monkeypatch.setenv("INCIDENT_KUBECONFIG", "/nope/missing.kubeconfig")
    with pytest.raises(CredentialError):
        _kubeconfig()


def test_ambiguous_clusters_refuse_to_guess(monkeypatch: Any) -> None:
    """Reporting against the wrong cluster is worse than refusing to start."""
    monkeypatch.delenv("INCIDENT_KUBECONFIG", raising=False)
    monkeypatch.delenv("INCIDENT_CONTEXT", raising=False)
    monkeypatch.setattr(
        _MINTED,
        lambda: [
            Path(".incident-reader.archdev.kubeconfig"),
            Path(".incident-reader.aks.kubeconfig"),
        ],
    )
    with pytest.raises(CredentialError, match="no cluster chosen"):
        _kubeconfig()


def test_context_selects_its_own_credential(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.delenv("INCIDENT_KUBECONFIG", raising=False)
    monkeypatch.setenv("INCIDENT_CONTEXT", "aks")
    monkeypatch.setattr(
        _MINTED,
        lambda: [
            _minted(tmp_path, "archdev", hours=8),
            _minted(tmp_path, "aks", hours=8),
        ],
    )
    assert str(_kubeconfig()).endswith(".incident-reader.aks.kubeconfig")


def test_unknown_context_names_the_command_to_run(monkeypatch: Any) -> None:
    monkeypatch.delenv("INCIDENT_KUBECONFIG", raising=False)
    monkeypatch.setenv("INCIDENT_CONTEXT", "nope")
    monkeypatch.setattr(_MINTED, lambda: [])
    with pytest.raises(CredentialError, match="incident-credentials --context nope"):
        _kubeconfig()


def _token(hours: float) -> str:
    """A service-account JWT expiring `hours` from now. Header and signature are
    filler: nothing here verifies the token, and nothing may."""
    exp = datetime.now(UTC) + timedelta(hours=hours)
    claims = json.dumps({"exp": int(exp.timestamp())}).encode()
    body = base64.urlsafe_b64encode(claims).decode().rstrip("=")
    return f"eyJhbGciOiJSUzI1NiJ9.{body}.signature"


def _minted(directory: Path, context: str, hours: float, token: str = "") -> Path:
    """A minted kubeconfig on disk, shaped like the real one."""
    path = directory / f".incident-reader.{context}.kubeconfig"
    path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "v1",
                "clusters": [{"name": context, "cluster": {"server": "https://x"}}],
                "users": [
                    {
                        "name": "incident-reader",
                        "user": {"token": token or _token(hours)},
                    }
                ],
            }
        )
    )
    return path


class TestRefresh:
    """An 8h credential expires every working day.

    So expiry is handled, not reported: the expiry is in a token this team
    minted itself, readable offline, and replaceable by the same code path the
    CLI uses. What must never happen is a silent escalation, or a refresh of a
    file the team did not write.
    """

    def test_an_expired_credential_is_reminted_and_the_run_continues(
        self, monkeypatch: Any, tmp_path: Path, capsys: Any
    ) -> None:
        path = _minted(tmp_path, "archdev", hours=-19.6)
        monkeypatch.setenv("INCIDENT_KUBECONFIG", str(path))
        monkeypatch.delenv("INCIDENT_NO_REFRESH", raising=False)
        minted_for: list[str | None] = []

        def fake_mint(context: str | None = None, **_: Any) -> Any:
            minted_for.append(context)
            _minted(tmp_path, "archdev", hours=8)
            return _Minted(can_read=True, can_write=False)

        monkeypatch.setattr(f"{_CREDENTIALS}.mint", fake_mint)
        assert _kubeconfig() == str(path)
        assert minted_for == ["archdev"]
        # Announced on stderr: it used your admin rights to write to a cluster.
        assert "minted a fresh read-only token" in capsys.readouterr().err

    def test_a_credential_about_to_expire_is_reminted_too(
        self, monkeypatch: Any, tmp_path: Path
    ) -> None:
        """A token with two minutes left would die mid-investigation."""
        monkeypatch.setenv(
            "INCIDENT_KUBECONFIG", str(_minted(tmp_path, "archdev", hours=0.03))
        )
        monkeypatch.delenv("INCIDENT_NO_REFRESH", raising=False)
        calls: list[str | None] = []
        monkeypatch.setattr(
            f"{_CREDENTIALS}.mint",
            lambda context=None, **_: (
                calls.append(context),
                _Minted(can_read=True, can_write=False),
            )[1],
        )
        _kubeconfig()
        assert calls == ["archdev"]

    def test_a_refresh_that_escalates_is_refused(
        self, monkeypatch: Any, tmp_path: Path
    ) -> None:
        """Fail closed: a writable credential is not this team's to use."""
        monkeypatch.setenv(
            "INCIDENT_KUBECONFIG", str(_minted(tmp_path, "archdev", hours=-1))
        )
        monkeypatch.setattr(
            f"{_CREDENTIALS}.mint",
            lambda **_: _Minted(can_read=True, can_write=True),
        )
        with pytest.raises(CredentialError, match="not read-only"):
            _kubeconfig()

    def test_a_failed_refresh_names_the_command_to_run(
        self, monkeypatch: Any, tmp_path: Path
    ) -> None:
        """No ambient context, no rights, no cluster: say so and stop."""
        monkeypatch.setenv(
            "INCIDENT_KUBECONFIG", str(_minted(tmp_path, "archdev", hours=-1))
        )

        def explode(**_: Any) -> Any:
            raise RuntimeError("context 'archdev' not found in kubeconfig")

        monkeypatch.setattr(f"{_CREDENTIALS}.mint", explode)
        with pytest.raises(CredentialError) as caught:
            _kubeconfig()
        message = str(caught.value)
        assert "not found in kubeconfig" in message
        assert "incident-credentials --context archdev" in message

    def test_a_credential_we_did_not_mint_is_never_rewritten(
        self, monkeypatch: Any, tmp_path: Path
    ) -> None:
        """An operator's own kubeconfig is not ours to replace."""
        theirs = tmp_path / "my-own.kubeconfig"
        theirs.write_text(_minted(tmp_path, "x", hours=-1).read_text())
        monkeypatch.setenv("INCIDENT_KUBECONFIG", str(theirs))

        def forbidden(**_: Any) -> Any:
            raise AssertionError("must not mint over a credential we did not write")

        monkeypatch.setattr(f"{_CREDENTIALS}.mint", forbidden)
        with pytest.raises(CredentialError, match="incident-credentials"):
            _kubeconfig()

    def test_refresh_can_be_switched_off(self, monkeypatch: Any, tmp_path: Path) -> None:
        """For anyone who does not want admin rights used implicitly."""
        monkeypatch.setenv(
            "INCIDENT_KUBECONFIG", str(_minted(tmp_path, "archdev", hours=-1))
        )
        monkeypatch.setenv("INCIDENT_NO_REFRESH", "1")

        def forbidden(**_: Any) -> Any:
            raise AssertionError("refresh was switched off")

        monkeypatch.setattr(f"{_CREDENTIALS}.mint", forbidden)
        with pytest.raises(CredentialError, match="expired 1h0m ago"):
            _kubeconfig()

    def test_a_live_credential_is_left_alone(
        self, monkeypatch: Any, tmp_path: Path
    ) -> None:
        path = _minted(tmp_path, "archdev", hours=8)
        monkeypatch.setenv("INCIDENT_KUBECONFIG", str(path))

        def forbidden(**_: Any) -> Any:
            raise AssertionError("a live credential must not be reminted")

        monkeypatch.setattr(f"{_CREDENTIALS}.mint", forbidden)
        assert _kubeconfig() == str(path)

    def test_a_token_with_no_readable_expiry_is_left_to_the_cluster(
        self, monkeypatch: Any, tmp_path: Path
    ) -> None:
        """An opaque token has no claim to read; the 401 path covers it."""
        path = _minted(tmp_path, "archdev", hours=0, token="opaque-not-a-jwt")
        monkeypatch.setenv("INCIDENT_KUBECONFIG", str(path))
        assert _kubeconfig() == str(path)

    def test_expiry_is_reported_in_days_once_it_is_stale(self) -> None:
        assert _ago(timedelta(hours=50)) == "2d2h ago"
        assert _ago(timedelta(minutes=45)) == "45m ago"


class TestUnauthorized:
    """Every API call funnels through one client, so 401 is translated once."""

    def test_a_401_becomes_an_actionable_credential_error(self, monkeypatch: Any) -> None:
        def reject(*_: Any, **__: Any) -> None:
            raise client.ApiException(status=401, reason="Unauthorized")

        monkeypatch.setattr(client.ApiClient, "request", reject)
        api = _AuthCheckedApiClient(".incident-reader.archdev.kubeconfig")
        with pytest.raises(CredentialError) as caught:
            api.request("GET", "https://x/api/v1/nodes")
        message = str(caught.value)
        assert "unauthorized (401)" in message
        assert "incident-credentials --context archdev" in message

    def test_a_403_is_left_alone(self, monkeypatch: Any) -> None:
        """403 is the read-only guarantee working, and the model is told so by
        `output.guard`. Translating it would hide a working credential."""

        def forbid(*_: Any, **__: Any) -> None:
            raise client.ApiException(status=403, reason="Forbidden")

        monkeypatch.setattr(client.ApiClient, "request", forbid)
        api = _AuthCheckedApiClient("whatever")
        with pytest.raises(client.ApiException) as caught:
            api.request("GET", "https://x/api/v1/nodes")
        assert caught.value.status == 403
