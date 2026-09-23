# CLAUDE.md — swarmr-kube

## Overview

Kubernetes incident response team for [swarmr](https://github.com/azyphon/swarmr-lib). Diagnoses a live cluster and proves the root cause. An incident commander delegates in parallel to four read-only domain investigators, then a critic independently tries to disprove the resulting hypothesis before it is reported.

Read-only twice over: the credential grants only `get/list/watch`, and Deep Agents filesystem permissions deny writes outside `evidence/`. Nothing about the target cluster is hardcoded — `discovery.py` profiles the live cluster at build time and the profile is injected into every prompt.

- **Distribution:** `swarmr-kube` (`src/swarmr_kube`, hatchling)
- **Python:** >=3.13
- **Deps:** `swarmr>=1.0,<2`, `kubernetes>=32`, `pyyaml>=6`
- **Entry point:** `swarmr.teams` group → `k8s_incident = "swarmr_kube:TEAM"`
- **Script:** `incident-credentials`

**The roster.** `commander` orchestrates and holds no cluster tools of its own. `workload` asks whether the container itself is failing; `network` whether traffic can reach a serving backend; `storage` whether the pod is blocked before it ever started; `platform` whether placement, capacity or node architecture is the problem. `critic` independently tries to disprove whatever hypothesis those four produce.

## Entry Points

### The team (`__init__.py` → `TEAM`)

Reached through `swarmr`'s surfaces, not its own:

```
teams --target k8s_incident
teams k8s_incident "payments.demo.local returns 502, namespace demo"
```

Over MCP the tool is `start_k8s_incident`.

Importing this module must stay cheap: it is what `teams --list` and the MCP server read to publish the team. `build`, `profile` and `render_report` are declared with `Lazy`; only `digest` and `is_error` — plain string handling — are imported directly.

### Credentials CLI (`credentials_cli.py` → `incident-credentials`)

```
incident-credentials --list
incident-credentials --context archdev
incident-credentials --context my-aks --ttl 2h
incident-credentials --print-manifest
```

Creates the `incident-reader` ServiceAccount and ClusterRole through the API, mints an 8h token, writes `.incident-reader.<context>.kubeconfig` at mode 600, then asks the API server to confirm the credential can list pods and cannot delete them. Exit 1 on a failed read-only check. Argument parsing and printing only; the minting logic is importable from `credentials.py` without a parser.

**Environment:** `INCIDENT_KUBECONFIG` (exact path), `INCIDENT_CONTEXT` (context name), `INCIDENT_NO_REFRESH=1` (disable auto-refresh), `INCIDENT_CACHE_TTL` (tool cache seconds, default 45), `INCIDENT_E2E=1` (enable the live e2e test), `KUBECONFIG` (first entry read when minting). Model credentials come from `swarmr` (`KIMI_*`).

## Architecture

**Team declaration**\
`__init__.py` — the `Team` object: name, summary, routing description, vocabulary (`orchestrator="commander"`, `audit_agents=("critic",)`, `report_tool`, `digest`, `is_error`), roster, `prompt_hint`, and the four `Lazy` targets. Deleting this package removes the team completely; discovery is by entry point, so nothing else in the tree refers to it.

**Assembly**\
`agent.py` — `build(run)` and `profile_target()`. Stock Deep Agents: one `create_deep_agent` commander plus five `SubAgent` specialists reached through the built-in `task` tool. Holds the filesystem permission rule sets.

**Cluster profiling**\
`discovery.py` — `ClusterProfile`, `profile_cluster()`, `render_facts()`, `render_routing()`. Every call is a read, once at startup, before the first token.

**Prompts**\
`prompts.py` — `commander`, `workload`, `network`, `storage`, `platform`, `critic`, the shared `INVESTIGATOR_CONTRACT`, and `SWEEP_REQUEST`. No cluster fact appears here; everything cluster-specific arrives as `facts` and `routing`.

**Connection**\
`client.py` — credential resolution, token expiry and refresh, `_AuthCheckedApiClient`, and the cached typed clients (`core_api`, `custom_api`, `dynamic_api`, `kube_clients`). `CredentialError` subclasses `swarmr`'s `TeamError`.

**Credentials**\
`rbac.py` — `READ_ONLY_RULES`, `ensure_rbac()`, `manifest()`. `credentials.py` — `mint()`, `contexts()`, `credential_path()`, `Minted`.

**Tools**\
`tools.py` — `k_get`, `k_events`, `k_logs`, `k_top`, and the per-role tool sets. `describe.py` — `k_describe`, the only tool with per-kind field knowledge. `registry.py` — `image_platforms`, `parse_ref`; the only tool that leaves the cluster.

**Result shaping**\
`output.py` — `emit` (prune + byte cap), `guard` (exception containment), `cached` (TTL memoisation). `projection.py` — `digest`, `age`, `container_state`, `clean_log`. `kinds.py` — `resolve_kind`. `digest.py` — `digest_result`, `is_tool_error`, the two fields `core` may call before a run.

**Report**\
`report_tool.py` — `file_incident_report` tool and `render_report_args`. `redaction.py` — `diagnosis`, `locator`, `one_line`, and the caveat text.

**Demo**\
`demo/*.yaml` — five staged faults, shipped in the wheel so `teams` users can reproduce a scenario.

## Roles and Tool Sets

`commander` holds `file_incident_report` and nothing else, under `_NO_WRITES`. `workload`, `network` and `storage` get `INVESTIGATOR_TOOLS` under `_EVIDENCE_ONLY`; `platform` gets `PLATFORM_TOOLS` under the same; `critic` gets `CRITIC_TOOLS` under `_NO_WRITES`.

`INVESTIGATOR_TOOLS = [k_get, k_describe, k_events, k_logs]`. `PLATFORM_TOOLS` swaps `k_logs` for `k_top` and adds `image_platforms`. `CRITIC_TOOLS` is everything. Only `platform` and `critic` get `image_platforms`, because only they are asked to make or check an architecture claim.

**The commander holds no cluster tools by design:** its context stays clean, and it cannot fabricate an observation it never received. The one tool it holds files the report.

**Permission rule sets are first-match-wins**, and a subagent that omits `permissions` inherits the parent's, so every role states its own. `_EVIDENCE_ONLY` allows `/evidence/**` *before* the catch-all `/**` deny — reversing that order silences the allow and no evidence can be written. Paths are absolute in the agent's virtual filesystem.

The commander is denied writes so planning lands in `write_todos`, which the harness already provides. Left free, it writes a scratch plan to `/tmp`, which is invisible to the caller and pure noise in the delegation trail.

## Cluster Discovery

`profile_cluster()` runs before the first token and populates `ClusterProfile`:

- **Version** via `VersionApi.get_code()`.
- **Nodes** — name, `kubernetes.io/arch`, roles from `node-role.kubernetes.io/*` labels, OS image, Ready condition, taints. `architectures` is the sorted distinct set; `heterogeneous` is `len > 1`.
- **Workload scan** — Deployments, DaemonSets and StatefulSets across all namespaces, bucketed by substring against `_INGRESS_SIGNS`, `_OBSERVABILITY_SIGNS`, `_GITOPS_SIGNS`. Substring matching because vendors prefix and suffix freely (`traefik`, `rke2-ingress-nginx`).
- **`absent`** — the observability and GitOps labels *not* found. Injected as "NOT present, so no evidence can possibly come from it … Never cite these systems", and the critic rejects any conclusion requiring one.
- **Storage** — provisioners, default StorageClass, and CSI workload pod names from `_CSI_HINTS`, so the storage investigator reads logs from a real pod name instead of guessing a vendor-specific one.
- **Namespaces** — non-system, excluding `kube-`, `openshift-`, `cattle-`, `gatekeeper-`, `tigera-` prefixes and `default`.
- **Restart baseline** — containers with restarts, bucketed by rounded hours since last termination, keeping cohorts of at least `max(3, len(pods) // 4)`. A cohort sharing one restart age is a single host event, not the incident. Rendered as `<known-baseline-noise>` and the critic is told to reject it by name.

`render_facts()` emits the `<cluster>` block; every line of it is measured, never assumed. Heterogeneous clusters get "image architecture mismatch is a first-class hypothesis"; homogeneous ones get "a mismatch would fail on every node equally, never on a subset".

`render_routing()` emits `<routing-mechanics>` written for the controller that is actually installed, from `_ROUTING_SEMANTICS` — a `(missing, refused)` status-code pair per controller. Traefik, ingress-nginx, HAProxy, Contour and Kong answer `503` for no backend and `502` for a refused dial; Istio answers `503` for both. With no controller detected, the block reasons at Service level only and explicitly forbids inventing HTTP status codes when nothing terminates HTTP.

`profile_target()` is separate from `build` because building constructs a model client. Fused, an operator asking "which cluster am I pointed at" got a missing-API-key error, having never contacted the cluster at all.

## Credential Resolution

`client._kubeconfig()`, in order:

1. `INCIDENT_KUBECONFIG`, if set — a missing file is an error.
2. `INCIDENT_CONTEXT`, naming a context that has been minted.
3. Exactly one minted credential on disk.
4. The in-cluster ServiceAccount, when running as a Pod (returns `None`).

**The ambient kubeconfig is deliberately not in that list.** On most clusters the default context is cluster-admin, so falling back to it would silently void the read-only guarantee. A missing credential is an error, not a reason to escalate privilege.

**Several minted credentials with no choice expressed is also an error.** An investigation reported against the wrong cluster is worse than one that refuses to start.

Minted files are found by globbing `.incident-reader*.kubeconfig` across every parent of the package plus cwd — a search rather than a fixed parent depth, because an installed package sits at a different depth than a source checkout.

## Token Refresh

An 8h token expires every working day, and the old failure mode was a 401 raised sixty frames deep in the generated client. `_ensure_live` reads the `exp` claim out of the kubeconfig's inline tokens *before opening a connection* and re-mints when under `_REFRESH_MARGIN` (5 minutes) remains, announcing it on stderr.

The claim is read, never verified — the API server is the only thing entitled to validate the token. An opaque or malformed token simply has no readable expiry and falls to the 401 path.

Three limits:

- **Only files this team minted are ever rewritten.** The gate is the `.incident-reader.<context>.kubeconfig` filename, which also carries the context, so the remedy message can name the exact command instead of a placeholder. Any other kubeconfig is reported, never replaced.
- **A refreshed credential that can do more than read is refused** rather than used, via `Minted.ok`.
- **Refresh never settles an ambiguous cluster choice.** Ambiguity is an error before this point, because refreshing every candidate would be picking a cluster to investigate.

`INCIDENT_NO_REFRESH=1` turns it off.

`_AuthCheckedApiClient.request` translates 401 once for every typed API, since `CoreV1Api`, `CustomObjectsApi` and `DynamicClient` all funnel through `ApiClient.request`. It covers what offline expiry checking cannot: a token revoked mid-run, a rotated in-cluster ServiceAccount, an operator-supplied kubeconfig with an opaque token. Only 401 is claimed — a 403 is a working credential doing its job, and `output.guard` explains it to the model as feedback.

## RBAC

`rbac.READ_ONLY_RULES` is the single definition of the team's reach, read-only by construction: `get`, `list`, `watch` only, with no `create`, `update`, `patch` or `delete` verb anywhere. Defined in Python rather than a YAML file so it cannot drift from the code depending on it; `manifest()` renders the same rules as YAML for GitOps, and `ensure_rbac()` converts the snake_case keys into client models.

Groups covered: core (pods, `pods/log`, services, endpoints, nodes, namespaces, events, PVCs, PVs, configmaps), `apps`, `discovery.k8s.io`, `networking.k8s.io`, `gateway.networking.k8s.io`, `traefik.io`/`traefik.containo.us`, `storage.k8s.io`, `metrics.k8s.io`, `events.k8s.io`.

`ensure_rbac` is idempotent, treating 409 as success — except for the ClusterRole, which is **replaced** on conflict so a rule added to `READ_ONLY_RULES` actually takes effect.

`credentials.mint()` uses your admin credentials for the chosen context to do the setup, requests a bound expiring token through the TokenRequest API, embeds the CA inline so the result is portable, writes at mode 600, then verifies with **the minted credential rather than the admin one** — the guarantee is about what that file can do. A source context with no CA is refused outright rather than writing a kubeconfig that cannot verify the API server.

## Tool Design

**No shell, and no kubectl string synthesis.** The model picks a tool and typed arguments; the tool builds the API call. Nothing the model emits reaches a shell.

**The boundary is the credential, not the prompt.** Every call rides a ServiceAccount holding only `get/list/watch`.

**Every tool wears the same three wrappers**, applied `@tool(parse_docstring=True)` → `@guard` → `@cached`:

- `guard` turns any failure into text the model can act on. An unhandled exception inside a tool aborts the whole LangGraph run and takes every concurrent investigator down with it; a bad argument is feedback, not a fatal condition. 403 is explained as the read-only design, 404 as a name/namespace check, `CredentialError` as its own sentence.
- `cached` memoises identical reads for `CACHE_TTL` (45s). Four investigators on one incident independently issue the same `k_get` and `k_events` calls, and each duplicate costs a round trip and a full result's worth of tokens. The TTL is deliberately short — an incident is a moving target and a stale endpoint list is worse than a slow one. `INCIDENT_CACHE_TTL=0` disables it.
- `emit` prunes server bookkeeping (`managedFields`, `resourceVersion`, `uid`, `generation`, `selfLink`, `creationTimestamp`, `finalizers`, plus two noisy annotations) and caps at `MAX_BYTES = 12_000` with a message telling the model to narrow the query rather than page. `ownerReferences` is deliberately kept: it is how a subagent walks pod → replicaset → deployment without guessing from labels.

**`k_get` without `name` returns compact rows** from `projection.digest`, with per-kind shaping for Pod, Node, Service, EndpointSlice, workload kinds and PVC. Full objects are 4–10 KB each, so a three-pod list overruns any byte cap and truncates mid-object, hiding the very field being looked for. A list answers "which object is suspect"; `k_describe` then answers "why".

**`k_describe` is the highest-signal first call**: it correlates an object's status with the events the control plane emitted about it, so a separate `k_events` call for the same object is redundant. It is the only tool carrying kind-specific field knowledge, and an unrecognised kind gets the whole spec — guessing which of a CRD's fields matter is worse than paying for all of them.

**`k_logs` cleans two forms of waste.** The Kubernetes client returns a `str` that is really the *repr* of bytes, beginning `b'` with escape sequences as six characters each; ANSI colour is stripped, and runs of identical lines are collapsed by comparing the message only, since the timestamp makes every line unique. An empty stream is returned as an explicit finding — a container that produced no output is consistent with a process that failed before it could log.

**`kinds.resolve_kind` normalises whatever the model wrote.** Discovery is exact-match while models write any case and plurality (`volumeattachment`, `EndpointSlices`, `ingressroutes`) and reach for kubectl abbreviations (`deploy`, `pvc`). Order: exact and capitalised kind, then de-pluralised, then plural resource name variants, then `shortNames` **asked of the API server** rather than a hardcoded table that would rot and miss CRDs. Several groups serving one Kind resolve to the shortest group name, which is the canonical one rather than a deprecated alias.

**`registry.image_platforms` speaks the OCI distribution API**, not the Kubernetes API — the only tool that leaves the cluster, and the only proof of an architecture claim. Anonymous pull tokens for Docker Hub and GHCR; Quay and `registry.k8s.io` need none. `parse_ref` treats a leading segment as a registry only when a path follows it: without the slash test, `nginx:1.29` parses as host `nginx` and port `1.29`. A single-arch manifest falls through to a config blob read for its real `os/architecture`.

## Prompt Design

Two conventions every investigator shares, stated in `INVESTIGATOR_CONTRACT`:

- **A clean domain is a real answer.** "Not my domain, here is why" is the most useful thing an investigator can say when it is true.
- **Findings return through the task result.** Bulk evidence goes to `evidence/<domain>.md` and the finding cites the path. The commander never inherits raw JSON.

The contract also caps output at 12 lines in a fixed `VERDICT / EVIDENCE / INFERENCE` shape, budgets about 8 cluster calls, requires independent reads batched into one turn, forbids re-reading, and explicitly tells investigators that `grep`, `glob` and `ls` operate on their own scratch filesystem — not the cluster, not any node — so there is nothing there to find.

**The commander is prohibited from enumerating what to check.** Its dispatches are one sentence: symptom, namespace or workload, time window. Telling a specialist what to look for narrows what it looks at, and the commander does not yet know where the fault is — which is the whole reason it delegates. `swarmr`'s `FirstRoundBriefing` enforces this in the harness for the first dispatch to each specialist; the prompt covers later rounds.

**The critic receives the hypothesis alone** — no reasoning, no attribution, no investigator text, and no instructions on how to check it. A checklist from the commander leaks its reasoning and biases the adjudication. `audit_agents=("critic",)` exempts it from the briefing rewrite and makes `core` echo its input verbatim so the adjudication can be audited. It rules `confirmed | refuted | unproven`, and the commander may resubmit at most twice.

**The critic cannot make an outbound HTTP request**, so it can never observe a status code itself; it is told to verify the mechanism from cluster state and the routing block rather than treat that as a gap.

**Domain-specific traps encoded in the prompts:**

- `storage` must pick the right half of the CSI driver: a PVC stuck `Pending` is a *provisioning* failure whose evidence is in the controller pod, while a Bound PVC with a pod stuck `ContainerCreating` is a *mount* failure whose evidence is in the node plugin on `spec.nodeName`. A hung provisioner logs the operation it started and then stops, so an absent error is still the finding.
- `storage` also owns the absence of Warnings: a PVC can sit Pending forever with only Normal events while the pod reports `FailedScheduling "pod has unbound immediate PersistentVolumeClaims"` — a symptom of storage, not capacity, and `platform` will see the same event.
- `platform` owns architecture mismatch and must prove it with `image_platforms` rather than pattern-matching a symptom. The mismatch appears in two distinct places: at pull time as `no match for platform in manifest`, and at exec time as `exec format error` / `StartError`. If the image genuinely publishes the node's architecture, it must say architecture is not the cause.
- `workload` treats an empty log stream from an instantly-terminated container as evidence in itself, reports the exit code verbatim, and leaves the explanation to `platform`.

**"No incident found" is a valid outcome.** Declaring an unhealthy-looking cluster actually healthy is explicitly valuable; inventing a fault to look useful is prohibited.

## Report Filing

The commander's last action is one `file_incident_report` call. Its arguments **are** the report: `symptom`, `root_cause`, `evidence`, `critic_ruling`, `fix_object`, `fix_locator`, `dismissed`. The tool body returns only a receipt; the caller reads the filed arguments off the run stream, which is what makes the filing deterministic to capture and visible in the delegation trail.

A tool rather than `response_format=ToolStrategy(...)`: that sets `tool_choice="required"`, which this model rejects outright while thinking is enabled (*"tool_choice 'required' is incompatible with thinking enabled"*).

Two failure modes made prose-only reporting unreliable — the commander sometimes stopping after the critic's verdict, leaving verdicts but no findings, and providers returning content blocks that naive text extraction discards.

## Redaction

The team reads cluster state, so it can observe a fault but cannot validate a correction — it cannot run the parser or the rollout that would prove one. Four prompt attempts failed: told to verify, the model certified; told to withhold, it certified; told to point rather than prescribe, it prescribed. So the policy is enforced in code on the render path, and the caveats are template text the model never phrases.

The render path is the only place this can live: the filed report is emitted from the tool call arguments *before* the tool body runs, so nothing the tool itself does can protect what the caller receives.

- **`locator(value)`** drops a `fix_locator` whole when `_PRESCRIPTIVE` matches an instruction-to-change or claim-about-afterwards verb. Dropped rather than clipped, because a prescription with its verb removed is still a prescription — and the object it points at is reported separately as `fix_object`.
- **`diagnosis(root_cause)`** drops any *sentence* matching `_COUNTERFACTUAL` — `instead of`, `rather than`, `should be/read/have`, `expected`, `typo/misspelling for`, `correctly spelled`. A live run filed "instead of `worker_connections`", invalid in that container's config context, so acting on it would have reproduced the outage.
- **Sentence granularity is deliberate.** Two earlier versions excised the clause and left mangled punctuation or swallowed the trailing half; nothing is rewritten now, a sentence is kept whole or dropped whole, and `OMITTED_NOTE` labels the gap rather than silently shortening the finding.
- **No membership test can vet the offered value.** A string appearing in evidence proves occurrence, not correctness, and `80` is a substring of `8080`.

`LOCATION_CAVEAT` accompanies every located finding: location only, decide and validate the change yourself.

## Design Patterns

**One responsibility per module**, stated in each module docstring: `client` gets a connection, `output` shapes a result, `kinds` normalises a kind, `rbac` defines policy, `redaction` suppresses, `prompts` is text only.

**Measured, never assumed** — every cluster fact in a prompt comes from a live read at build time, so the same code runs against any cluster.

**Lazy heavyweight fields** — `build`, `profile` and `render_report` behind `Lazy`, so publishing the MCP surface costs 133 modules instead of 4533.

**Defence in depth** — read-only by credential (RBAC verbs), by tool surface (no mutating tool exists), and by filesystem permission.

**Fail closed** — no ambient-kubeconfig fallback, no CA-less kubeconfig, ambiguous cluster choice refused, an over-privileged refreshed credential refused.

**Wrapper stack over per-call discipline** — `guard`/`cached`/`emit` on every tool rather than each call site remembering; 401 translated once in `ApiClient.request` rather than at each API.

**Policy in code, not prose** — RBAC as a Python tuple, redaction as regexes on the render path. Both were things a prompt could not hold.

**Ask the server** — `shortNames` from discovery, permissions from `SelfSubjectAccessReview`, expiry from the token's own claim.

**Errors as feedback** — a tool failure returns text the model can act on; only a credential failure is fatal, and it is a `TeamError` so both surfaces print one sentence.

**Cached module-level clients** — `functools.cache` on `_api_client`, `dynamic_api`, `core_api`, `custom_api`, `resolve_kind`, `_short_names`.

## Testing

No cluster, no model calls. `testpaths = ["src"]`, tests beside the code they cover, excluded from the wheel.

- `test_contract.py` — the important one. Pins the vocabulary `core` reads off this team, that no mutating tool exists in any role's set, that the permission rule sets grant and deny in the right order, that `build`/`profile`/`render_report` stay behind `Lazy`, and — in a subprocess, since this process has already imported the agent module — that `build_server()` loads no `swarmr_kube.agent` and stays under 1500 modules. That last claim can only be made here: core ships no team, so it has nothing to prove unimported.
- `test_credentials.py` — resolution order, expiry parsing, refresh gating, minting.
- `test_discovery.py`, `test_projection.py`, `test_digest.py`, `test_registry.py`, `test_report.py` — pure functions over fixture payloads.
- `test_e2e.py` — marked `e2e`, needs a live cluster and a model key, gated behind `INCIDENT_E2E=1`.

```
python3 -m venv .venv && source .venv/bin/activate
pip install -e ../swarmr-lib -e ".[dev]"
pytest
INCIDENT_E2E=1 pytest -s
ruff check . && pyright
```

Unlike core, this project **does** pin `venvPath="."`/`venv=".venv"`: that is the only project-level signal an editor's pyright reads, and without it the language server type-checks against whatever bare interpreter is on PATH. CI therefore builds `.venv` too, so the one path is correct everywhere.

CI (`.github/workflows/ci.yml`) uses `uv`, installs `swarmr` from git `@main` **before** the editable install — the `swarmr>=1.0,<2` pin resolves against an index that does not carry it — then runs `pytest`, `ruff check .` and `pyright` from `.venv/bin/python`.

## Dependencies

- `kubernetes>=32` — the generated client. `CoreV1Api`, `AppsV1Api`, `StorageV1Api`, `VersionApi`, `CustomObjectsApi` for metrics, `DynamicClient` for CRDs and kind discovery, `AuthorizationV1Api` for the read-only self-check, and the TokenRequest API for minting.
- `pyyaml>=6` — kubeconfig reading and RBAC manifest emission.
- `swarmr>=1.0,<2` — capped to a minor because `Team`, `RunContext`, `TeamBuild`, `Lazy`, `TeamError`, `core.middleware` and the `swarmr.teams` group are an ABI this package implements. From it: `build_model` (never a model constructed here), `AnnounceName`, `FirstRoundBriefing`, `Attribution`, `clip`.
- `deepagents` / `langchain-core` — reached transitively for `create_deep_agent`, `SubAgent`, `FilesystemPermission` and the `@tool` decorator.
- No HTTP client dependency: `registry.py` uses `urllib.request`.
- Dev: `pytest`, `pytest-cov`, `ruff` (line length 90; `E,F,I,UP,B,SIM,RUF`), `pyright` (standard mode, 3.13).
