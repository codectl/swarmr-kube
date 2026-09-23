"""The `incident-credentials` command line.

One responsibility: argument parsing and human-readable output. Kept apart from
`credentials.py` so the minting logic can be imported and tested without an
argument parser, and so a CLI concern — printing rather than raising — never
leaks into the library.

    incident-credentials --list
    incident-credentials --context archdev
    incident-credentials --context my-aks --ttl 2h
    incident-credentials --print-manifest
"""

from __future__ import annotations

import argparse
import sys

from swarmr_kube.credentials import (
    DEFAULT_TTL,
    contexts,
    credential_path,
    mint,
)
from swarmr_kube.rbac import manifest

__all__ = ["main"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="incident-credentials",
        description="Mint a read-only kubeconfig for the Kubernetes incident team.",
    )
    parser.add_argument("--context", help="kubeconfig context to mint against")
    parser.add_argument("--ttl", default=DEFAULT_TTL, help="token lifetime, e.g. 8h")
    parser.add_argument(
        "--list", action="store_true", help="list kubeconfig contexts and exit"
    )
    parser.add_argument(
        "--print-manifest",
        action="store_true",
        help="print the RBAC as YAML and exit, applying nothing",
    )
    args = parser.parse_args(argv)

    if args.print_manifest:
        print(manifest(), end="")
        return 0

    if args.list:
        names, active = contexts()
        for name in names:
            marker = "*" if name == active else " "
            path = credential_path(name)
            state = "minted" if path.is_file() else "-"
            print(f"{marker} {name:<32} {state}")
        return 0

    try:
        result = mint(context=args.context, ttl=args.ttl)
    except Exception as exc:  # a CLI reports; it does not traceback
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"context: {result.context}")
    print(f"server:  {result.server}")
    print(f"wrote:   {result.path}  (ttl={args.ttl}, mode 600)")
    print(f"can list pods:   {'yes' if result.can_read else 'NO'}")
    print(f"can delete pods: {'no' if not result.can_write else 'YES — NOT READ-ONLY'}")
    if not result.ok:
        print("error: the minted credential failed its read-only check", file=sys.stderr)
        return 1
    print(f"\nUse it with:  INCIDENT_KUBECONFIG={result.path} teams k8s_incident '…'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
