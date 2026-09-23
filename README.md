# swarmr-kube

Kubernetes incident response team for
[swarmr](https://github.com/azyphon/swarmr-lib). Diagnoses a live cluster and
proves the root cause.

Read-only twice over: the credential grants only get/list/watch, and filesystem
permissions deny writes outside `evidence/`. Nothing about the cluster is
hardcoded — the team profiles it at startup and injects what it found into every
prompt.

## Install

Core and this team must land in the **same environment**.

```
uv tool install git+https://github.com/azyphon/swarmr \
  --with git+https://github.com/azyphon/swarmr-kube \
  --with-executables-from swarmr-kube
```

That exposes `teams`, `teams-mcp` and `incident-credentials` on your PATH.
`--with-executables-from` is required for the third.

```
teams --target k8s_incident
teams k8s_incident "payments.demo.local returns 502, namespace demo"
```

Over MCP the tool is `start_k8s_incident`.

## Credentials

This team needs a **read-only** credential. It refuses your ambient kubeconfig,
which is usually cluster-admin.

```
incident-credentials --list
incident-credentials --context archdev
incident-credentials --print-manifest
```

That creates the `incident-reader` ServiceAccount and ClusterRole, mints an 8h
token, writes `.incident-reader.<context>.kubeconfig` at mode 600, then asks the
API server to confirm the credential can list pods and cannot delete them.

Each cluster gets its own credential file. Selection is explicit:
`INCIDENT_KUBECONFIG` (exact path), else `INCIDENT_CONTEXT` (context name), else
the single minted credential. Several credentials with no choice expressed is an
error rather than a guess.

The 8h token refreshes itself: every run reads the expiry before opening a
connection and re-mints when under five minutes remain. Only files this team
minted are ever rewritten. `INCIDENT_NO_REFRESH=1` turns it off.

Design notes and internals: [CLAUDE.md](CLAUDE.md).
