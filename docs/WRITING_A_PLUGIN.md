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
    base_url: https://dokploy.internal
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
