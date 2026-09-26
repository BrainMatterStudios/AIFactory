# Writing a plugin — extend the factory for your own tools

You extend the factory by **implementing a contract and registering a name** — you
never fork the factory's source. This guide walks the full path with a real example:
a **Dokploy** connector that lets the observe loop read your deployment status and
logs.

There are four extension surfaces. All follow the same shape.

| Surface | Contract | You provide |
|---|---|---|
| **Adapter** | one of the six `Protocol`s in `software_factory/adapters/base.py` | a class + a `@register(kind, name)` builder |
| **Collector** | `.scan(data) -> [CheckResult]` (`software_factory/loop/collectors.py`) | a class with a `name` and `scan` |
| **Persona** | a catalog YAML entry | a row in a project persona pack |
| **Dials** | the manifest | `routing`, `routines`, `budget`, `build.verify_cmd` |

---

## 1. Write the adapter

Pick the adapter *kind* your tool belongs to. Infra/observability tools (Dokploy,
Docker, K8s, Datadog) are **`observe`** adapters — read-only `run_status()` +
`recent_logs()`. (Test tools like Maestro usually aren't adapters at all — put them in
`build.verify_cmd`; see §6.)

```python
# mycompany_factory/dokploy.py
from software_factory.adapters.base import RunStatus
from software_factory.adapters.registry import register
import os, urllib.request, json

class DokployObserve:
    """Read-only Dokploy connector: deployment status + recent logs."""

    def __init__(self, *, base_url: str, token_env: str = "DOKPLOY_TOKEN", app_ids=()):
        self.base_url = base_url.rstrip("/")
        self.token_env = token_env
        self.app_ids = list(app_ids)

    def _get(self, path: str):
        token = os.environ.get(self.token_env)
        if not token:
            raise KeyError(f"{self.token_env} is unset")  # fail loud, never guess
        req = urllib.request.Request(f"{self.base_url}{path}",
                                     headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())

    # --- the ObserveAdapter contract ---
    def run_status(self):
        out = []
        for app in self.app_ids:
            data = self._get(f"/api/application.one?applicationId={app}")
            ok = data.get("applicationStatus") == "done"
            out.append(RunStatus(name=app, ok=ok, detail=data.get("applicationStatus", "")))
        return out

    def recent_logs(self, target: str, *, lines: int = 200):
        return self._get(f"/api/application.logs?applicationId={target}&lines={lines}")

@register("observe", "dokploy")           # ← now selectable as provider: dokploy
def _build(config):
    return DokployObserve(
        base_url=config["base_url"],
        token_env=config.get("token_env", "DOKPLOY_TOKEN"),
        app_ids=config.get("app_ids", ()),
    )
```

Two rules the built-in adapters follow and yours should too:
- **Fail closed.** If a required secret/DSN is unset, raise — never fall back to a
  weaker default (this is why the postgres adapter errors instead of guessing).
- **Read-only for `observe`/`data`.** The ceiling depends on the factory never being
  able to mutate infra; an observe adapter must only read.

## 2. Make the factory load your module

The registry only knows about code that has been imported. Two ways to ensure your
`@register` runs — pick either.

**a) List it in the manifest (zero packaging).** Drop the module next to your
`factory.config.yaml` (the factory adds the manifest's directory to the import path) or
anywhere else on your `PYTHONPATH`, and name it:

```yaml
factory:
  plugins: [mycompany_factory.dokploy]     # imported before any adapter is built
  observe:
    provider: dokploy
    base_url: https://dokploy.example.test
    app_ids: [api, worker]
```

**b) Ship a pip package with an entry point (auto-discovered).** In your plugin
package's `pyproject.toml`:

```toml
[project.entry-points."software_factory.plugins"]
mycompany = "mycompany_factory.dokploy"
```

Now `pip install mycompany-factory` registers the connector with **no manifest edit** —
the factory discovers the `software_factory.plugins` group on startup (the same pattern
pytest and flake8 use).

## 3. Verify it

```bash
factory doctor      # builds every adapter; prints `plugins: loaded mycompany_factory.dokploy`
```

If `doctor` builds the `dokploy` observe adapter without error, you're wired. A typo in
the provider name yields a clear `no observe adapter named 'dokploy' registered` —
which means the module wasn't loaded (check `plugins:` / the entry point).

## 4. Add a collector (turn logs into verdicts)

An adapter gets you the *signal*; a **collector** turns it into a PASS/WARN/FAIL the
loop can queue. Collectors are loaded via the `observe.collectors` manifest hook:

```python
# mycompany_factory/checks.py
from software_factory.loop.collectors import CheckResult, CheckVerdict

class ErrorRateCheck:
    name = "error_rate"
    def scan(self, data):                       # `data` is your DataAdapter
        (errs,) = data.query("SELECT count(*) FROM logs WHERE level='error'")[0]
        v = CheckVerdict.FAIL if errs > 100 else CheckVerdict.PASS
        return [CheckResult("logs:error_rate", v, {"errors": errs})]

collectors = [ErrorRateCheck()]
```

```yaml
factory:
  observe:
    provider: dokploy
    collectors: mycompany_factory.checks:collectors   # module:attr
```

## 5. Add domain personas (optional)

Drop a YAML pack in your project and point the manifest at it. New roles are usable
immediately as prompt-personas:

```yaml
# team-packs/fintech.yaml
personas:
  - name: payments-compliance-officer
    model: opus
    author: prompt
    frequency: context
    phase: review
    role: Reviews money-movement changes for PCI/AML exposure; can raise a security block.
```

```yaml
factory:
  personas:
    packs: [team-packs]      # dirs of *.yaml, relative to the manifest
```

`factory personas` will list your roles alongside the built-ins.

## 6. Test tools (Maestro, Playwright, pytest)

These usually **aren't adapters** — they're the build loop's gate. Put them in
`build.verify_cmd`; the orchestrator already refuses to open a PR unless that command
passes:

```yaml
factory:
  build:
    verify_cmd: "maestro test .maestro/ && pytest -q"
```

Only reach for a dedicated adapter if you want *structured* per-flow results (which
Maestro flow failed, screenshots) to feed the judge or be filed as issue evidence —
that's a richer extension worth doing deliberately, not by default.

## 7. Capability providers: declare narrowly, observe exactly

A capability provider supplies one role-bound workflow guarantee. It first
**declares** the capabilities its implementation can supply, then emits a
runtime **observation** that confirms or fails those capabilities for one exact
`CapabilityContext`. A declaration is inventory, not authorization. Only a
same-source observation whose context digest matches the current repository,
issue, parent/configuration digests, base revision, and workspace fingerprint
can satisfy an obligation.

| Role | Owns evidence for |
|---|---|
| `controller` | exact approval pause, controller state, and controller-side publication ceiling |
| `workspace` | isolated worktree and its exact base identity |
| `executor` | bounded writable paths and executor-side containment |
| `verifier` | approved objective verification |
| `scanner` | bounded credential-scan evidence and redacted findings |
| `analyzer` | required analyzer execution/evidence availability |
| `runner` | only properties the legacy runner can actually prove |

## 8. Optional Lima validation-cell backend

The `software_factory.adapters.optional.lima_leash` plugin registers four linked
entries: runner `lima-leash-claude`, workspace `lima-cell`, executor provider
`lima-leash-executor`, and analyzer `lima-harness`.  They are transport
separate: the runner declares no executor or controller capability, and a
successful agent turn is never authority evidence.

Every entry must receive the same normalized cell settings — `instance`, exact
`instance_id`, absolute `controller_state_path`, `bridge_version`,
`policy_digest`, `workspace_root`, `network_profile`, both image digests, the
installed bridge interpreter/module/console-shim/wrapper digests, every measured
Leash entry/package/launcher/native/environment/Node/git identity,
`workspace_context_digest`, `manifest_digest`, `execution_policy_digest`,
`phase_artifacts`, and `phase_writable_paths`. The controller state path must
identify the instance's owner-private `state.json`. Before every guest dispatch,
each role acquires the controller's instance-transition lock and authenticates
that state, its configured lifecycle, and its exact owner-private
`factory.config.json`; it holds the lock until the dispatch ends. The controller
compares the roles' exact shared fields and
normalized configuration digest before it dispatches an executor-bound turn;
each role retains a separate role-authority digest for its role-only options.
All digest fields are lowercase SHA-256 values (the instance identity uses the
`sha256:` prefix). `lima-cell` additionally requires a locally verified source
bundle digest. Its `lima://INSTANCE/CONTEXT` path is an opaque identity, never a
host filesystem path.

Unknown settings are rejected. A scoped executor turn must use
`ScopedRunnerAdapter.run_scoped_agent`; there is no legacy `run_agent` fallback.
The executor provider fails all of its declarations when guest bridge, instance,
policy, workspace, mount, network, or runtime-version evidence differs. The
`lima-harness` analyzer is invoked by the fixed bounded bridge workspace action
and authenticates the current guest surface before returning the packaged
HarnessAnalyzer report; it does not execute repository content.

The controller role is reserved to AIFactory. Plugins cannot register or
instantiate a controller provider, and an external workspace provider cannot
replace the workspace that the configured workspace factory actually created.
The configured workspace-factory source, the materialized workspace's source,
and its native declaration must be identical.

The following minimal executor plugin uses the actual provider API. It has no
third-party imports at module import time. Lima and Leash remain optional
integrations, so a core-only installation can import the provider API without
either dependency. The supplied digest is evidence for the exact execution
policy selected in the configuration; the factory compares it with that policy
rather than trusting the plugin to choose a policy.

```python
# mycompany_factory/executor.py
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from software_factory.adapters.base import CapabilityProvider
from software_factory.core.design import (
    Capability,
    CapabilityContext,
    ProviderCapabilityDeclaration,
    ProviderCapabilityObservation,
    ProviderRole,
    capability_context_sha256,
)
from software_factory.core.design.provider_registry import register_capability_provider


class ExampleExecutor:
    source = "example-executor"
    provider_role = ProviderRole.EXECUTOR

    def __init__(self, execution_policy_digest: str) -> None:
        self._execution_policy_digest = execution_policy_digest

    def capability_declaration(self) -> ProviderCapabilityDeclaration:
        return ProviderCapabilityDeclaration(
            "provider-capability-declaration-v1",
            self.source,
            self.provider_role,
            frozenset({Capability.BOUNDED_WRITABLE_PATHS}),
        )

    def observe_capabilities(
        self, *, context: CapabilityContext
    ) -> ProviderCapabilityObservation:
        return ProviderCapabilityObservation(
            "provider-capability-observation-v1",
            self.source,
            self.provider_role,
            capability_context_sha256(context),
            frozenset({Capability.BOUNDED_WRITABLE_PATHS}),
            frozenset(),
            (self._execution_policy_digest,),
        )


def build_executor(options: Mapping[str, Any]) -> CapabilityProvider:
    policy_digest = options.get("execution_policy_digest")
    if (
        type(policy_digest) is not str
        or len(policy_digest) != 64
        or any(character not in "0123456789abcdef" for character in policy_digest)
    ):
        raise ValueError("execution_policy_digest must be a lowercase SHA-256 digest")
    return ExampleExecutor(policy_digest)


register_capability_provider("example-executor", ProviderRole.EXECUTOR, build_executor)
```

Load it through `factory.plugins`, then configure its exact source and options
under `factory.build.capability_providers`. If the build declares an execution
policy, the provider's `execution_policy_digest` must be that policy's canonical
SHA-256 digest. A real executor must make its observation fail when containment
cannot be observed; it must not convert an unavailable probe into confirmation.

Provider-aware configuration uses `design-config-v2`, which binds configured
providers, execution policy, and workspace-factory selection into the Design
authority digest. `design-config-v1` cannot authorize those runtime inputs.
Released runner declaration/observation records remain replayable, but project
only to `ProviderRole.RUNNER`; a capability name in a v1 record never grants
controller, workspace, executor, verifier, scanner, or analyzer authority.

Provider evidence authorizes only its named workflow capability. It never
authorizes a push, merge, deploy, database connection, or approval. Those stay
separate controller and operator decisions, even when an executor confirms a
merge or deployment prohibition.

---

## The whole model in one line

**Implement a contract → register a name → load your module (manifest `plugins:` or an
entry point) → select it in the manifest.** That is the entire extension framework, and
it is the same for every surface.


---

## Contract notes for adapter and workspace authors

Two requirements were added after this guide was first written. Both are the kind
of thing that fails silently if you miss them, so they are called out here rather
than left to the Protocol docstrings.

**A `SourceAdapter` must raise `DedupUnavailable` when a fingerprint lookup could
not run.**

```python
from software_factory.adapters.base import DedupUnavailable

def find_by_fingerprint(self, fingerprint, *, include_closed=False):
    resp = self._api.search(fingerprint)
    if not resp.ok:
        raise DedupUnavailable(f"board search failed: {resp.status}")
    ...
```

Returning `None` on failure is read as "nothing matched", which means "file it" —
so one rate-limited lookup posts a duplicate of every open ticket. The loop
catches this exception and files nothing for that pass.

**A `Workspace` must implement `changed_files()`**, returning every path the build
would push, relative to the tree — including work the agent already committed:

```python
def changed_files(self) -> list[str]:
    return sorted(set(self._diff_since_base()) | self._dirty() | self._untracked())
```

The secret gate scans exactly this list before pushing, and it **fails closed**: a
workspace that cannot report its diff blocks the build rather than being waved
through. Anything missing from the list would be pushed unscanned while the gate
reported clean.

`preserve()` is **optional** — implement it if you want a stopped build's work to
survive `cleanup()`. Whatever it writes must be invisible to `changed_files()`;
the reference implementation snapshots to a side ref (`refs/factory/wip/<branch>`)
precisely so the work is recoverable without becoming pushable, re-anchorable, or
counted as "this run produced something".
