# Controller-Managed Validation-Cell Image Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the two slow StrongDM image pulls out of Lima cloud-init and into one closed, controller-owned `bootstrap-images` creation stage without changing later image attestation or external-target scope.

**Architecture:** Lima installs a fixed, self-removing root helper but does not execute either image pull during boot. After successful `limactl start`, `ValidationCellController.create()` invokes that helper with a fixed argument vector and a 1,800-second subprocess bound; the existing bootstrap attestation later measures and binds both immutable repository digests.

**Tech Stack:** Python 3.13, pytest, POSIX shell embedded in Lima YAML, Lima 2.2.0, Docker Engine, `uv build`.

**Spec:** `docs/superpowers/specs/2026-09-02-controller-managed-validation-cell-image-bootstrap-design.md`

## Global Constraints

- Work only in `<repository-worktree>` on branch `docs/operational-validation-stage1`.
- Read the specification before changing code and use `.venv/bin/python` for project tests.
- Modify only `software_factory/execution/assets/lima.yaml`, `software_factory/execution/cell.py`, and `tests/test_validation_cell_assets.py` unless a failing test proves another file is required.
- The helper path is exactly `/usr/local/sbin/aifactory-bootstrap-images`.
- It accepts zero arguments and pulls only `public.ecr.aws/s5i7k8t3/strongdm/coder:latest`, then `public.ecr.aws/s5i7k8t3/strongdm/leash:latest`.
- Initial Lima start and `bootstrap-images` each use a 1,800-second Python subprocess bound. All other ordinary creation operations retain the existing 600-second default.
- Preserve empty host mounts, denied dynamic forwarding, root-owned authority, the current Cedar policy, model-auth isolation, and existing digest-qualified image attestation.
- A failure leaves lifecycle `pending`, records only canonical `failure_stage: "bootstrap-images"`, and runs no later creation stage.
- Do not authenticate, import, seal, run an agent, contact an external target, push, merge, publish, deploy, delete a forensic cell, or write production state.
- Use conventional local commits with `Co-Authored-By: Codex <noreply@openai.com>`.

---

### Task 1: Add the Closed Image-Bootstrap Transition

**Files:**
- Modify: `software_factory/execution/assets/lima.yaml:70-130`
- Modify: `software_factory/execution/cell.py:40-115`
- Modify: `software_factory/execution/cell.py:850-915`
- Test: `tests/test_validation_cell_assets.py:430-520`
- Test: `tests/test_validation_cell_assets.py:1190-1340`
- Test: `tests/test_validation_cell_assets.py:1620-1860`

**Interfaces:**
- Consumes: `ValidationCellController._run(...) -> bytes`, `_create_boundary(...)`, `_json_bytes(...)`, `CODER_IMAGE`, and `LEASH_IMAGE`.
- Produces: `BOOTSTRAP_IMAGES = "/usr/local/sbin/aifactory-bootstrap-images"`, creation stage `bootstrap-images`, and helper stdout exactly `b'{"hydrated":true}\n'`.
- Preserves: `_guest_bootstrap()` remains the sole authority that resolves and records both immutable image digests and references.

- [ ] **Step 1: Read the governing design and current flow**

```bash
sed -n '1,320p' docs/superpowers/specs/2026-09-02-controller-managed-validation-cell-image-bootstrap-design.md
sed -n '35,125p' software_factory/execution/cell.py
sed -n '835,1065p' software_factory/execution/cell.py
sed -n '55,175p' software_factory/execution/assets/lima.yaml
```

Expected: YAML executes both pulls and the controller moves directly from `start` to `machine-id`.

- [ ] **Step 2: Write the failing asset test**

Add to `tests/test_validation_cell_assets.py`:

```python
def test_image_bootstrap_helper_is_fixed_self_removing_and_not_run_by_cloud_init(
    tmp_path: Path,
) -> None:
    yaml = pytest.importorskip("yaml")
    from software_factory.execution.cell import asset_bytes

    provision = yaml.safe_load(asset_bytes("lima.yaml"))["provision"][0]["script"]
    marker = (
        "install -o root -g root -m 0755 /dev/stdin "
        "/usr/local/sbin/aifactory-bootstrap-images <<'SH'\n"
    )
    assert provision.count(marker) == 1
    before, body_and_after = provision.split(marker, 1)
    helper, after = body_and_after.split("\nSH\n", 1)
    helper += "\n"
    outer_provision = before + "\n:\n" + after
    subprocess.run(
        ["/bin/sh", "-n"], input=helper.encode(), check=True, capture_output=True
    )
    assert "docker pull " not in outer_provision
    executable = [
        line.strip()
        for line in helper.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert executable == [
        "set -eu",
        '[ "$#" -eq 0 ] || exit 1',
        "/usr/bin/docker pull public.ecr.aws/s5i7k8t3/strongdm/coder:latest >/dev/null",
        "/usr/bin/docker pull public.ecr.aws/s5i7k8t3/strongdm/leash:latest >/dev/null",
        "/usr/bin/rm -f -- /usr/local/sbin/aifactory-bootstrap-images",
        "printf '%s\\n' '{\"hydrated\":true}'",
    ]
    helper_path = tmp_path / "aifactory-bootstrap-images"
    helper_path.write_text(helper, encoding="utf-8")
    helper_path.chmod(0o700)
    rejected = subprocess.run(
        [str(helper_path), "unexpected"], check=False, capture_output=True, text=True
    )
    assert (rejected.returncode, rejected.stdout, rejected.stderr) == (1, "", "")
```

In the existing readiness-order test, replace `before_image_pulls` with a partition at the image-helper install marker. Assert the existing package, pnpm, Docker-service, authority-root, workspace-root, and readiness-helper prerequisites all occur in `before_image_helper`.

- [ ] **Step 3: Run the asset test and observe the red state**

```bash
.venv/bin/python -m pytest \
  tests/test_validation_cell_assets.py::test_image_bootstrap_helper_is_fixed_self_removing_and_not_run_by_cloud_init \
  tests/test_validation_cell_assets.py::test_readiness_elevates_only_rootful_docker_without_granting_user_socket_access -q
```

Expected: FAIL because the new helper does not exist and image pulls still execute in cloud-init.

- [ ] **Step 4: Install the helper instead of running pulls during boot**

Keep `systemctl enable --now docker` after the readiness prerequisites. Replace the two direct pulls in `lima.yaml` with:

```sh
      # Image hydration is controller-owned because Lima 2.2 gives each boot
      # requirement only about ten minutes. This fixed one-shot helper accepts
      # no image input and removes itself after both pulls succeed.
      install -o root -g root -m 0755 /dev/stdin /usr/local/sbin/aifactory-bootstrap-images <<'SH'
      #!/bin/sh
      set -eu
      [ "$#" -eq 0 ] || exit 1
      /usr/bin/docker pull public.ecr.aws/s5i7k8t3/strongdm/coder:latest >/dev/null
      /usr/bin/docker pull public.ecr.aws/s5i7k8t3/strongdm/leash:latest >/dev/null
      /usr/bin/rm -f -- /usr/local/sbin/aifactory-bootstrap-images
      printf '%s\n' '{"hydrated":true}'
      SH
```

Do not add a background process, readiness sentinel, host cache, configurable argument, or alternate registry.

- [ ] **Step 5: Make the asset tests green and validate Lima syntax**

```bash
.venv/bin/python -m pytest \
  tests/test_validation_cell_assets.py::test_image_bootstrap_helper_is_fixed_self_removing_and_not_run_by_cloud_init \
  tests/test_validation_cell_assets.py::test_readiness_elevates_only_rootful_docker_without_granting_user_socket_access \
  tests/test_validation_cell_assets.py::test_noble_provisioner_installs_every_invoked_package_tool_before_use \
  tests/test_validation_cell_assets.py::test_noble_provisioner_disables_background_package_mutation_before_bootstrap -q
lima_tmp=$(mktemp -d)
LIMA_HOME="$lima_tmp" limactl template validate software_factory/execution/assets/lima.yaml
rm -r "$lima_tmp"
```

Expected: four tests PASS and Lima reports `OK`.

- [ ] **Step 6: Write failing controller tests and extend only the fake runtime**

Teach `FakeRuntime.__call__` this one exact success response:

```python
if argv == [
    "limactl", "--tty=false", "shell", "aifactory-stage1", "--",
    "/usr/bin/sudo", "-n", "--", "/usr/local/sbin/aifactory-bootstrap-images",
]:
    return subprocess.CompletedProcess(argv, 0, _canonical({"hydrated": True}), b"")
```

Add the exact order and timeout test:

```python
def test_create_runs_bounded_image_bootstrap_before_identity_or_transport(
    tmp_path: Path,
) -> None:
    controller, runtime, _client = _controller(tmp_path)
    observed: list[tuple[list[str], object]] = []

    def capture(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        observed.append((argv, kwargs.get("timeout")))
        return runtime(argv, **kwargs)

    controller._runner = capture
    _created(controller, tmp_path)
    helper = [
        "limactl",
        "--tty=false",
        "shell",
        "aifactory-stage1",
        "--",
        "/usr/bin/sudo",
        "-n",
        "--",
        "/usr/local/sbin/aifactory-bootstrap-images",
    ]
    helper_index = next(
        index for index, (argv, _timeout) in enumerate(observed) if argv == helper
    )
    machine_index = next(
        index
        for index, (argv, _timeout) in enumerate(observed)
        if argv[-1:] == ["/etc/machine-id"]
    )
    assert helper_index == 2
    assert helper_index < machine_index
    assert observed[helper_index][1] == 1_800
    long_calls = [(argv, timeout) for argv, timeout in observed if timeout == 1_800]
    assert [argv for argv, _timeout in long_calls] == [
        ["limactl", "start", "--timeout=30m", "aifactory-stage1"],
        helper,
    ]
```

Add the complete noncanonical-response test:

```python
def test_create_refuses_noncanonical_image_bootstrap_success(tmp_path: Path) -> None:
    from software_factory.execution.cell import CellError

    controller, runtime, _client = _controller(tmp_path)

    def malformed(
        argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if argv[-1:] == ["/usr/local/sbin/aifactory-bootstrap-images"]:
            return subprocess.CompletedProcess(argv, 0, b'{"hydrated": true}\n', b"")
        return runtime(argv, **kwargs)

    controller._runner = malformed
    wheel = tmp_path / "software_factory-0.3.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    with pytest.raises(CellError, match="bootstrap-images-invalid"):
        controller.create(instance="aifactory-stage1", wheel=wheel)
    state = json.loads(
        (tmp_path / "controller" / "aifactory-stage1" / "state.json").read_bytes()
    )
    assert state["lifecycle"] == "pending"
    assert state["create_stage"] == "bootstrap-images"
    assert state["failure_stage"] == "bootstrap-images"
    assert "failure_detail" not in state
```

Add `bootstrap-images` to every parameterized closed creation-stage matrix,
including failure, interruption, and coherent-state tests. In runtime stage
classifiers, match the fixed helper path before generic guest actions.

- [ ] **Step 7: Run the controller tests and observe the red state**

```bash
.venv/bin/python -m pytest \
  tests/test_validation_cell_assets.py::test_create_runs_bounded_image_bootstrap_before_identity_or_transport \
  tests/test_validation_cell_assets.py::test_create_refuses_noncanonical_image_bootstrap_success \
  tests/test_validation_cell_assets.py::test_create_failure_persists_only_canonical_private_stage_evidence -q
```

Expected: FAIL because the controller does not call or recognize `bootstrap-images`.

- [ ] **Step 8: Implement the controller stage**

Add beside the other bootstrap constants:

```python
BOOTSTRAP_IMAGES = "/usr/local/sbin/aifactory-bootstrap-images"
```

Add `"bootstrap-images"` to `_CREATE_STAGES`. Immediately after successful
`start` and before `read_machine_id`, add:

```python
def bootstrap_images() -> None:
    hydrated = self._run(
        [
            "limactl", "--tty=false", "shell", instance, "--",
            "/usr/bin/sudo", "-n", "--", BOOTSTRAP_IMAGES,
        ],
        timeout_seconds=1_800,
    )
    if hydrated != _json_bytes({"hydrated": True}, newline=True):
        raise CellError("bootstrap-images-invalid")

self._create_boundary(instance, state, "bootstrap-images", bootstrap_images)
```

Do not parse image identity here, pass input bytes, expose stderr, add a CLI option, or modify `_guest_bootstrap()`.

- [ ] **Step 9: Run all validation-cell asset tests**

```bash
.venv/bin/python -m pytest tests/test_validation_cell_assets.py -q
```

Expected: PASS with only existing environment-dependent skips.

- [ ] **Step 10: Verify scope and commit**

```bash
.venv/bin/python -m ruff check software_factory/execution/cell.py tests/test_validation_cell_assets.py
git diff --check
git diff -- software_factory/execution/assets/lima.yaml software_factory/execution/cell.py tests/test_validation_cell_assets.py
```

Expected: no file outside the three approved paths and no image-measurement change in `_guest_bootstrap()`.

```bash
git add software_factory/execution/assets/lima.yaml software_factory/execution/cell.py tests/test_validation_cell_assets.py
git commit -m "fix: move image hydration outside Lima boot" \
  -m "- install a fixed self-removing image bootstrap helper
- record a bounded controller-owned creation stage
- retain measured digest attestation and fail-closed evidence" \
  -m "Co-Authored-By: Codex <noreply@openai.com>"
```

Expected: one local commit, clean worktree, no push.

---

### Task 2: Verify the Integrated Lifecycle and Obtain Independent Review

**Files:**
- Verify: `software_factory/execution/assets/lima.yaml`
- Verify: `software_factory/execution/cell.py`
- Verify: `tests/test_validation_cell_assets.py`
- Verify: `tests/test_validation_cell_integration.py`
- Verify: `tests/test_execution_bridge.py`

**Interfaces:**
- Consumes: the Task 1 commit and approved specification.
- Produces: test and review evidence authorizing one disposable live-cell retry; no source change unless a concrete finding is reproduced test-first.

- [ ] **Step 1: Run the focused lifecycle and bridge suites**

```bash
.venv/bin/python -m pytest \
  tests/test_validation_cell_assets.py \
  tests/test_validation_cell_integration.py \
  tests/test_execution_bridge.py \
  tests/test_lima_client.py \
  tests/test_lima_leash_adapter.py -q
```

Expected: PASS with only existing declared skips.

- [ ] **Step 2: Run static and package checks**

```bash
.venv/bin/python -m ruff check software_factory tests
.venv/bin/python -m compileall -q software_factory tests
git diff --check
lima_tmp=$(mktemp -d)
LIMA_HOME="$lima_tmp" limactl template validate software_factory/execution/assets/lima.yaml
rm -r "$lima_tmp"
```

Expected: all commands succeed and Lima reports the template `OK`.

- [ ] **Step 3: Run the full repository suite and compare baseline failures**

```bash
.venv/bin/python -m pytest -q
```

Expected: no new failure. If the branch still reports the three known baseline
failures below, reproduce them against the parent commit before accepting them:

```text
tests/test_design_adversarial.py::*final-capability-auth*
tests/test_judge_gate_integrity.py::test_a_runner_that_predates_the_tools_argument_still_works
tests/test_local_publication_adversarial.py::test_local_validation_reconstructs_exact_commit_without_remote_or_source_mutation
```

Any additional failure blocks the live retry until diagnosed.

- [ ] **Step 4: Request an independent read-only review**

Give the reviewer the specification and Task 1 commit. Require answers to:

```text
1. Can either image pull still execute during Lima cloud-init?
2. Can operator-controlled input reach the root helper?
3. Can helper success replace or influence immutable image attestation?
4. Are start and bootstrap-images the only 1,800-second operations?
5. Does every helper failure stop before identity, transport, authentication, import, and execution?
6. Does self-removal occur only after both pulls succeed?
```

Expected: ACCEPT with no Critical or Important finding. Reproduce any finding
locally; fix it via a red test and local follow-up commit before retrying.

- [ ] **Step 5: Confirm the branch and retained cells are safe**

```bash
git status --short --branch
git log -3 --oneline
limactl list --json | python3 -c '
import json, sys
for line in sys.stdin:
    item = json.loads(line)
    name = item.get("name", "")
    if name.startswith("aifactory-stage1-containment-"):
        print(name, item.get("status"))
'
```

Expected: clean worktree; implementation remains local; retained failed cells
are stopped; no shared-state action occurred.

---

### Task 3: Run One Gated Live Cell and Capture Pre-Authentication Evidence

**Files:**
- Read: exact committed AIFactory checkout
- Create outside repository: `<operator-state-dir>/stage1-operational-validation/builds/<HEAD>/software_factory-0.3.0-py3-none-any.whl`
- Create outside repository: `<operator-state-dir>/stage1-operational-validation/aifactory-stage1-containment-20260902-07-doctor.json`
- On failure only: `<operator-state-dir>/stage1-operational-validation/aifactory-stage1-containment-20260902-07-blocked-before-execution.json`

**Interfaces:**
- Consumes: clean reviewed Task 1 commit, `factory validation-cell create`, Lima 2.2.0, and private controller state.
- Produces: either lifecycle `created` plus a canonical pre-auth doctor record, or a stopped retained cell plus canonical `blocked-before-execution` evidence.
- Does not produce: authentication, repository import, dependencies, seal, configuration, containment probe, model run, or external-target change.

- [ ] **Step 1: Build and authenticate the exact-commit wheel**

```bash
test -z "$(git status --porcelain)"
head_commit=$(git rev-parse HEAD)
build_dir="<operator-state-dir>/stage1-operational-validation/builds/$head_commit"
mkdir -p "$build_dir"
chmod 0700 "$build_dir"
uv build --wheel --out-dir "$build_dir"
wheel="$build_dir/software_factory-0.3.0-py3-none-any.whl"
chmod 0600 "$wheel"
shasum -a 256 "$wheel"
python3 -m zipfile -l "$wheel" | rg 'software_factory/execution/(cell.py|assets/lima.yaml)'
```

Expected: one owner-private wheel under the exact commit directory containing both changed production files.

- [ ] **Step 2: Inspect the packaged boundary before launch**

```bash
inspect_dir=$(mktemp -d)
python3 -m zipfile -e "$wheel" "$inspect_dir"
rg -n 'aifactory-bootstrap-images|bootstrap-images|docker pull|timeout_seconds=1_800' \
  "$inspect_dir/software_factory/execution/cell.py" \
  "$inspect_dir/software_factory/execution/assets/lima.yaml"
rm -r "$inspect_dir"
```

Expected: YAML only installs the fixed helper; the controller invokes the same
path; no configurable image reference enters the helper vector.

- [ ] **Step 3: Create exactly one new disposable cell**

```bash
instance=aifactory-stage1-containment-20260902-07
.venv/bin/factory validation-cell create --instance "$instance" --wheel "$wheel"
```

Monitor the same process without restarting it. During the image transfer,
private controller state must show `create_stage: "bootstrap-images"` while
cloud-init already reports `status: done`. Expected final state is lifecycle
`created` with no `create_stage`, `failure_stage`, or `failure_detail`.

- [ ] **Step 4: Verify live phase separation**

```bash
limactl shell "$instance" -- cloud-init status --long
python3 - <<'PY'
from pathlib import Path

name = "aifactory-stage1-containment-20260902-07"
stderr = (Path.home() / ".lima" / name / "ha.stderr.log").read_text()
stdout = (Path.home() / ".lima" / name / "ha.stdout.log").read_text()
if "The optional requirement 1 of 1 is satisfied" not in stderr:
    raise SystemExit("optional readiness did not succeed")
if "The final requirement 1 of 1 is satisfied" not in stderr:
    raise SystemExit("Lima final provisioning did not succeed")
if '"degraded":true' in stdout:
    raise SystemExit("Lima retained a degraded requirement result")
PY
```

Expected: cloud-init `status: done`; optional and final requirements succeeded;
no degraded host-agent result. Controller state and later attestation—not
cloud-init—prove image hydration.

- [ ] **Step 5: Capture and validate the pre-auth doctor record**

```bash
operator_evidence="<operator-state-dir>/stage1-operational-validation"
umask 077
doctor_record="$operator_evidence/$instance-doctor.json"
.venv/bin/factory validation-cell doctor --instance "$instance" --json > "$doctor_record"
chmod 0600 "$doctor_record"
python3 -m json.tool "$doctor_record" >/dev/null
```

The exact record must report Linux, `host_mounts: []`, guest-native
`/srv/aifactory/workspaces`, Leash 1.1.7 / `5bf1c64`,
`network_profile: model-only-v1`, `/usr/sbin/nft`, packaged policy and bridge
identities, and both digest-qualified StrongDM image references.

Verify the one-shot helper is absent:

```bash
if limactl shell "$instance" -- /usr/bin/test -e /usr/local/sbin/aifactory-bootstrap-images
then
  printf '%s\n' 'bootstrap image helper still exists after success' >&2
  exit 1
fi
```

Expected: doctor record is canonical and private; helper absence returns
nonzero; lifecycle remains `created` for the existing human-auth gate.

- [ ] **Step 6: Fail closed if any live check fails**

```bash
limactl stop aifactory-stage1-containment-20260902-07
limactl list --json | rg 'aifactory-stage1-containment-20260902-07'
```

Persist one owner-private canonical record with schema
`stage1-operator-failure-v1`, classification `blocked-before-execution`, the
exact instance, `external_target_touched: false`, and `retained: true`. Add only
evidenced bounded fields such as `create_stage`, `failure_stage`, `reason`,
`root_cause`, and `wheel_digest`; never include raw output. Do not delete,
resume, patch, authenticate, import, or create another cell without a new
diagnosis and review.

- [ ] **Step 7: Hand off at the human-authentication gate**

On success, report the exact commit, wheel digest, instance and lifecycle,
doctor-record path, digest-qualified images, and proof of Lima/controller phase
separation. Confirm external targets remained untouched and no push, merge,
deployment, or production write occurred.

Stop there. The next operation is the interactive Claude login from
`docs/OPERATING.md`, which requires the human and is outside this plan.
