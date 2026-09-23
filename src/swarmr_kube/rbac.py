"""What this team is allowed to see, in one place.

One responsibility: the RBAC policy. `READ_ONLY_RULES` is the single definition
of the team's reach — read-only by construction, with no create, update, patch
or delete verb anywhere — and this module renders it, as YAML for GitOps and
into client models for the API. Defining it in Python rather than a YAML file
keeps it from drifting away from the code that depends on it.

Applying it and minting a token against it is `credentials.py`.
"""

from __future__ import annotations

from typing import Any

import yaml
from kubernetes import client

__all__ = [
    "READ_ONLY_RULES",
    "ROLE_NAME",
    "SA_NAME",
    "SA_NAMESPACE",
    "ensure_rbac",
    "manifest",
]

SA_NAME = "incident-reader"
SA_NAMESPACE = "kube-system"
ROLE_NAME = "incident-reader"

# The single definition of what this team may see. Verbs are read-only by
# construction: no create, update, patch or delete anywhere. Keys are the client
# model's snake_case; `manifest()` converts them for YAML output.
READ_ONLY_RULES: tuple[dict[str, list[str]], ...] = (
    {
        "api_groups": [""],
        "resources": [
            "pods",
            "pods/log",
            "services",
            "endpoints",
            "nodes",
            "namespaces",
            "events",
            "persistentvolumeclaims",
            "persistentvolumes",
            "configmaps",
        ],
        "verbs": ["get", "list", "watch"],
    },
    {
        "api_groups": ["apps"],
        "resources": ["deployments", "replicasets", "statefulsets", "daemonsets"],
        "verbs": ["get", "list", "watch"],
    },
    {
        "api_groups": ["discovery.k8s.io"],
        "resources": ["endpointslices"],
        "verbs": ["get", "list", "watch"],
    },
    {
        "api_groups": ["networking.k8s.io"],
        "resources": ["ingresses", "networkpolicies"],
        "verbs": ["get", "list", "watch"],
    },
    {
        "api_groups": ["gateway.networking.k8s.io"],
        "resources": ["gateways", "httproutes"],
        "verbs": ["get", "list", "watch"],
    },
    {
        "api_groups": ["traefik.io", "traefik.containo.us"],
        "resources": ["ingressroutes", "middlewares"],
        "verbs": ["get", "list", "watch"],
    },
    {
        "api_groups": ["storage.k8s.io"],
        "resources": ["storageclasses", "volumeattachments"],
        "verbs": ["get", "list", "watch"],
    },
    {
        "api_groups": ["metrics.k8s.io"],
        "resources": ["pods", "nodes"],
        "verbs": ["get", "list"],
    },
    {
        "api_groups": ["events.k8s.io"],
        "resources": ["events"],
        "verbs": ["get", "list", "watch"],
    },
)


def ensure_rbac(api: Any) -> None:
    """Create or update the ServiceAccount, ClusterRole and binding. Idempotent."""
    core = client.CoreV1Api(api)
    rbac = client.RbacAuthorizationV1Api(api)

    sa = client.V1ServiceAccount(
        metadata=client.V1ObjectMeta(name=SA_NAME, namespace=SA_NAMESPACE)
    )
    try:
        core.create_namespaced_service_account(SA_NAMESPACE, sa)
    except client.ApiException as exc:
        if exc.status != 409:
            raise

    role = client.V1ClusterRole(
        metadata=client.V1ObjectMeta(name=ROLE_NAME),
        rules=[client.V1PolicyRule(**rule) for rule in READ_ONLY_RULES],
    )
    try:
        rbac.create_cluster_role(role)
    except client.ApiException as exc:
        if exc.status != 409:
            raise
        # Replace, so a rule added to READ_ONLY_RULES actually takes effect.
        rbac.replace_cluster_role(ROLE_NAME, role)

    binding = client.V1ClusterRoleBinding(
        metadata=client.V1ObjectMeta(name=ROLE_NAME),
        role_ref=client.V1RoleRef(
            api_group="rbac.authorization.k8s.io", kind="ClusterRole", name=ROLE_NAME
        ),
        subjects=[
            client.RbacV1Subject(
                kind="ServiceAccount", name=SA_NAME, namespace=SA_NAMESPACE
            )
        ],
    )
    try:
        rbac.create_cluster_role_binding(binding)
    except client.ApiException as exc:
        if exc.status != 409:
            raise


def _rule_to_yaml(rule: dict[str, list[str]]) -> dict[str, list[str]]:
    """snake_case (client model) -> camelCase (Kubernetes YAML)."""
    return {
        "apiGroups" if key == "api_groups" else key: value for key, value in rule.items()
    }


def manifest() -> str:
    """The same RBAC as YAML, for teams that apply it through GitOps."""
    documents = [
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": SA_NAME, "namespace": SA_NAMESPACE},
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": ROLE_NAME},
            "rules": [_rule_to_yaml(rule) for rule in READ_ONLY_RULES],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": ROLE_NAME},
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": ROLE_NAME,
            },
            "subjects": [
                {
                    "kind": "ServiceAccount",
                    "name": SA_NAME,
                    "namespace": SA_NAMESPACE,
                }
            ],
        },
    ]
    return yaml.safe_dump_all(documents, sort_keys=False)
