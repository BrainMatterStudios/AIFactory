from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shlex
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

PROBE_IDS = (
    "filesystem-marker-read",
    "filesystem-write-control",
    "filesystem-traversal",
    "filesystem-other-workspace",
    "filesystem-operator",
    "filesystem-docker-socket",
    "filesystem-cedar",
    "filesystem-bridge",
    "filesystem-guest-authority",
    "filesystem-controller-evidence",
    "process-git-push",
    "process-gh",
    "process-kubectl",
    "process-terraform",
    "process-vercel",
    "process-flyctl",
    "process-docker",
    "process-sudo",
    "process-su",
    "process-ssh",
    "tamper-cedar",
    "tamper-bridge",
    "tamper-guest-authority",
    "tamper-controller-evidence",
    "network-api-anthropic",
    "network-claude",
    "network-mcp-proxy",
    "network-platform",
    "network-firewall-control",
    "network-github",
    "network-metadata",
    "network-rfc1918-10",
    "network-rfc1918-172",
    "network-rfc1918-192",
    "network-sqlserver",
    "network-postgres",
    "network-ssh",
)
POSITIVE_IDS = {
    "filesystem-marker-read",
    "filesystem-write-control",
    "network-api-anthropic",
    "network-claude",
    "network-mcp-proxy",
    "network-platform",
}
FIREWALL_CONTROL_ID = "network-firewall-control"
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = getattr(os, "O_DIRECTORY", 0)
REPO_ROOT = Path(__file__).resolve().parents[1]
PNPM_IDENTITY_FIELDS = (
    "pnpm_version",
    "pnpm_archive_digest",
    "pnpm_tree_digest",
    "pnpm_entrypoint_digest",
    "pnpm_entrypoint_path",
)
PNPM_IDENTITY = {
    "pnpm_version": "10.18.0",
    "pnpm_archive_digest": (
        "3967a3efe2909df305fec4b833a304dfca17c380b6bb77672f4dac4f2cdd3788"
    ),
    "pnpm_tree_digest": (
        "7cfb88c40ea232b1ac67f8115727ae5940a5bb17ffe91bfd75bb88fe01a66d4a"
    ),
    "pnpm_entrypoint_digest": (
        "b276da51dc8ca5b0d3ee3371695b50fc8b3244b281b091c63a3f082a88dadeb9"
    ),
    "pnpm_entrypoint_path": (
        "/opt/aifactory-cell/toolchains/pnpm-10.18.0/package/bin/pnpm.cjs"
    ),
}


class ClosedEvidenceError(ValueError):
    """A passing claim did not satisfy the integration test's closed schema."""


def _canonical(document: object, *, newline: bool = False) -> bytes:
    encoded = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return encoded + (b"\n" if newline else b"")


def _probe_set_digest() -> str:
    return hashlib.sha256(_canonical({"ids": list(PROBE_IDS)})).hexdigest()


def _expected_probe(probe_id: str) -> dict[str, str]:
    category = (
        "network"
        if probe_id.startswith("network-")
        else (
            "process"
            if probe_id.startswith("process-")
            else ("tamper" if probe_id.startswith("tamper-") else "filesystem")
        )
    )
    positive = probe_id in POSITIVE_IDS
    firewall_control = probe_id == FIREWALL_CONTROL_ID
    expectation = (
        "allowed" if positive else ("outer-denied" if firewall_control else (
            "denied" if category == "network" else "denied-or-absent"
        ))
    )
    if positive:
        observed, reason = "succeeded", "none"
    elif category == "network":
        observed, reason = "failed", "network-error"
    else:
        observed, reason = "absent", "not-found"
    return {
        "id": probe_id,
        "category": category,
        "expectation": expectation,
        "observed": observed,
        "reason": reason,
    }


def _authority_fixture() -> dict[str, Any]:
    return {
        "instance_id": "sha256:" + "1" * 64,
        "bootstrap": {
            "bridge_module_digest": "8" * 64,
            "input_digests": {"policy_digest": "9" * 64},
        },
        "request": {"context_digest": "2" * 64, "manifest_digest": "3" * 64},
        "configuration_digest": "4" * 64,
        "image_digest": "5" * 64,
        "leash_image_digest": "6" * 64,
        "seal": {"seal_digest": "7" * 64},
    }


def _passing_record() -> tuple[dict[str, Any], dict[str, Any]]:
    authority = _authority_fixture()
    identity = {
        "bridge_module_digest": "8" * 64,
        "image_digest": authority["image_digest"],
        "leash_image_digest": authority["leash_image_digest"],
        "manifest_digest": authority["request"]["manifest_digest"],
        "policy_digest": "9" * 64,
        "seal_digest": authority["seal"]["seal_digest"],
    }
    bridge_result = {
        "schema_version": "containment-probe-result-v1",
        "disposition": "passed",
        "reason": "none",
        "context_digest": authority["request"]["context_digest"],
        "identity": identity,
        "firewall": {
            "program_digest": "a" * 64,
            "drop_before": 0,
            "drop_after": 1,
            "cleanup_verified": True,
        },
        "probes": [_expected_probe(probe_id) for probe_id in PROBE_IDS],
    }
    record = {
        "schema_version": "containment-evidence-v1",
        "instance": "aifactory-stage1-fixture",
        "instance_id": authority["instance_id"],
        "context_digest": authority["request"]["context_digest"],
        "configuration_digest": authority["configuration_digest"],
        "image_digest": authority["image_digest"],
        "leash_image_digest": authority["leash_image_digest"],
        "manifest_digest": authority["request"]["manifest_digest"],
        "seal_digest": authority["seal"]["seal_digest"],
        "probe_set_digest": _probe_set_digest(),
        "freshness": {"pre": "b" * 64, "post": "b" * 64},
        "bridge_result": bridge_result,
        "disposition": "passed",
        "reason": "none",
    }
    return record, authority


def _read_owner_private_evidence(path: Path, *, expected_digest: str) -> dict[str, Any]:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or DIGEST.fullmatch(expected_digest) is None
        or path.name != f"{expected_digest}.json"
    ):
        raise ClosedEvidenceError("evidence-path-invalid")
    parent_fd = descriptor = -1
    try:
        parent_named = path.parent.lstat()
        if (
            stat.S_ISLNK(parent_named.st_mode)
            or not stat.S_ISDIR(parent_named.st_mode)
            or parent_named.st_uid != os.geteuid()
            or stat.S_IMODE(parent_named.st_mode) != 0o700
        ):
            raise ClosedEvidenceError("evidence-directory-unsafe")
        parent_fd = os.open(path.parent, os.O_RDONLY | DIRECTORY | NOFOLLOW)
        parent_opened = os.fstat(parent_fd)
        if (parent_named.st_dev, parent_named.st_ino) != (
            parent_opened.st_dev,
            parent_opened.st_ino,
        ):
            raise ClosedEvidenceError("evidence-directory-replaced")
        descriptor = os.open(path.name, os.O_RDONLY | NOFOLLOW, dir_fd=parent_fd)
        before = os.fstat(descriptor)
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size <= 1
            or before.st_size > MAX_EVIDENCE_BYTES
            or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise ClosedEvidenceError("evidence-file-unsafe")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, min(1024 * 1024, MAX_EVIDENCE_BYTES + 1 - size)):
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_EVIDENCE_BYTES:
                raise ClosedEvidenceError("evidence-file-oversized")
        after = os.fstat(descriptor)
        named_after = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        stable_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
        if (
            any(getattr(before, field) != getattr(after, field) for field in stable_fields)
            or (after.st_dev, after.st_ino) != (named_after.st_dev, named_after.st_ino)
        ):
            raise ClosedEvidenceError("evidence-file-replaced")
        payload = b"".join(chunks)
        if not payload.endswith(b"\n"):
            raise ClosedEvidenceError("evidence-document-noncanonical")
        document = json.loads(payload.decode("utf-8"))
        if type(document) is not dict or payload != _canonical(document, newline=True):
            raise ClosedEvidenceError("evidence-document-noncanonical")
        if hashlib.sha256(payload[:-1]).hexdigest() != expected_digest:
            raise ClosedEvidenceError("evidence-digest-mismatch")
        return document
    except ClosedEvidenceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ClosedEvidenceError("evidence-unreadable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)


def _digest(value: object) -> bool:
    return type(value) is str and DIGEST.fullmatch(value) is not None


def _pnpm_identity(value: Mapping[str, Any]) -> dict[str, Any]:
    return {field: value.get(field) for field in PNPM_IDENTITY_FIELDS}


def _validate_pnpm_lifecycle_authority(
    authority: Mapping[str, Any], *, doctor: Mapping[str, Any]
) -> None:
    """Authenticate pnpm across the configured lifecycle before the live probe."""
    try:
        bootstrap = authority["bootstrap"]
        dependencies = authority["dependencies"]
        for surface in (
            bootstrap,
            dependencies,
            doctor["guest"],
            doctor["observation"],
        ):
            if not isinstance(surface, Mapping) or _pnpm_identity(surface) != PNPM_IDENTITY:
                raise ClosedEvidenceError("pnpm-authority-invalid")

        seal_payload = {
            "bootstrap_digest": bootstrap["bootstrap_digest"],
            "dependency_tree_digest": dependencies["dependency_tree_digest"],
            "image": bootstrap["coder_image_reference"],
            "image_digest": authority["image_digest"],
            "leash_image": bootstrap["leash_image_reference"],
            "leash_image_digest": authority["leash_image_digest"],
            "input_digests": bootstrap["input_digests"],
            "manifest_digest": authority["request"]["manifest_digest"],
            **PNPM_IDENTITY,
        }
        if authority["seal"]["seal_digest"] != hashlib.sha256(
            _canonical(seal_payload)
        ).hexdigest():
            raise ClosedEvidenceError("pnpm-seal-authority-invalid")

        manifest_path = authority["manifest_path"]
        if type(manifest_path) is not str:
            raise ClosedEvidenceError("pnpm-configuration-invalid")
        document = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        if authority["configuration_digest"] != hashlib.sha256(
            _canonical(document)
        ).hexdigest():
            raise ClosedEvidenceError("pnpm-configuration-invalid")
        factory = document["factory"]
        option_sets = (
            factory["workspace"],
            factory["runner"],
            factory["build"]["design_analyzers"][0]["options"],
            factory["build"]["capability_providers"][0]["options"],
        )
        if any(_pnpm_identity(options) != PNPM_IDENTITY for options in option_sets):
            raise ClosedEvidenceError("pnpm-configuration-invalid")
    except ClosedEvidenceError:
        raise
    except (KeyError, TypeError, ValueError, OSError) as error:
        raise ClosedEvidenceError("pnpm-authority-invalid") from error


def _reject_sensitive_surface(value: object) -> None:
    forbidden_keys = {
        "authorization",
        "body",
        "credential",
        "credentials",
        "environment",
        "env",
        "host_path",
        "output",
        "path",
        "prompt",
        "response",
        "secret",
        "stderr",
        "stdout",
        "token",
        "url",
        "uri",
    }
    forbidden_values = (
        "http://",
        "https://",
        "/Users/",
        "/home/",
        "/root/",
        "anthropic_api_key",
        "authorization:",
        "bearer ",
        "credential=",
        "password=",
        "database_password=",
        "secret=",
        "token=",
    )
    if isinstance(value, Mapping):
        for key, child in value.items():
            if type(key) is not str or key.lower() in forbidden_keys:
                raise ClosedEvidenceError("evidence-sensitive-surface")
            _reject_sensitive_surface(child)
    elif isinstance(value, list):
        for child in value:
            _reject_sensitive_surface(child)
    elif type(value) is str and any(marker in value.lower() for marker in forbidden_values):
        raise ClosedEvidenceError("evidence-sensitive-surface")


def _validate_passing_evidence(
    record: Mapping[str, Any], *, instance: str, authority: Mapping[str, Any]
) -> None:
    try:
        record_fields = {
            "schema_version",
            "instance",
            "instance_id",
            "context_digest",
            "configuration_digest",
            "image_digest",
            "leash_image_digest",
            "manifest_digest",
            "seal_digest",
            "probe_set_digest",
            "freshness",
            "bridge_result",
            "disposition",
            "reason",
        }
        if type(record) is not dict or set(record) != record_fields:
            raise ClosedEvidenceError("evidence-schema-invalid")
        expected = {
            "instance_id": authority["instance_id"],
            "context_digest": authority["request"]["context_digest"],
            "configuration_digest": authority["configuration_digest"],
            "image_digest": authority["image_digest"],
            "leash_image_digest": authority["leash_image_digest"],
            "manifest_digest": authority["request"]["manifest_digest"],
            "seal_digest": authority["seal"]["seal_digest"],
        }
        if (
            record["schema_version"] != "containment-evidence-v1"
            or record["instance"] != instance
            or record["disposition"] != "passed"
            or record["reason"] != "none"
            or record["probe_set_digest"] != _probe_set_digest()
            or any(record[key] != value for key, value in expected.items())
            or not record["instance_id"].startswith("sha256:")
            or not _digest(record["instance_id"].removeprefix("sha256:"))
            or any(not _digest(record[key]) for key in expected if key != "instance_id")
        ):
            raise ClosedEvidenceError("evidence-authority-invalid")
        freshness = record["freshness"]
        if (
            type(freshness) is not dict
            or set(freshness) != {"pre", "post"}
            or not _digest(freshness["pre"])
            or freshness["post"] != freshness["pre"]
        ):
            raise ClosedEvidenceError("evidence-freshness-invalid")

        result = record["bridge_result"]
        result_fields = {
            "schema_version",
            "disposition",
            "reason",
            "context_digest",
            "identity",
            "firewall",
            "probes",
        }
        if type(result) is not dict or set(result) != result_fields:
            raise ClosedEvidenceError("probe-result-schema-invalid")
        if (
            result["schema_version"] != "containment-probe-result-v1"
            or result["disposition"] != "passed"
            or result["reason"] != "none"
            or result["context_digest"] != record["context_digest"]
        ):
            raise ClosedEvidenceError("probe-result-disposition-invalid")

        identity = result["identity"]
        identity_fields = {
            "bridge_module_digest",
            "image_digest",
            "leash_image_digest",
            "manifest_digest",
            "policy_digest",
            "seal_digest",
        }
        if (
            type(identity) is not dict
            or set(identity) != identity_fields
            or any(not _digest(value) for value in identity.values())
            or identity["bridge_module_digest"]
            != authority["bootstrap"]["bridge_module_digest"]
            or identity["image_digest"] != record["image_digest"]
            or identity["leash_image_digest"] != record["leash_image_digest"]
            or identity["manifest_digest"] != record["manifest_digest"]
            or identity["policy_digest"]
            != authority["bootstrap"]["input_digests"]["policy_digest"]
            or identity["seal_digest"] != record["seal_digest"]
        ):
            raise ClosedEvidenceError("probe-identity-invalid")

        firewall = result["firewall"]
        if (
            type(firewall) is not dict
            or set(firewall)
            != {"program_digest", "drop_before", "drop_after", "cleanup_verified"}
            or not _digest(firewall["program_digest"])
            or type(firewall["drop_before"]) is not int
            or type(firewall["drop_after"]) is not int
            or not 0 <= firewall["drop_before"] < firewall["drop_after"] <= 2**63 - 1
            or firewall["cleanup_verified"] is not True
        ):
            raise ClosedEvidenceError("probe-firewall-invalid")

        probes = result["probes"]
        if type(probes) is not list or len(probes) != len(PROBE_IDS):
            raise ClosedEvidenceError("probe-set-incomplete")
        for expected_id, item in zip(PROBE_IDS, probes, strict=True):
            baseline = _expected_probe(expected_id)
            if (
                type(item) is not dict
                or set(item) != {"id", "category", "expectation", "observed", "reason"}
                or item["id"] != expected_id
                or item["category"] != baseline["category"]
                or item["expectation"] != baseline["expectation"]
            ):
                raise ClosedEvidenceError("probe-item-invalid")
            if expected_id in POSITIVE_IDS:
                valid_outcome = (item["observed"], item["reason"]) == (
                    "succeeded",
                    "none",
                )
            elif item["category"] == "network":
                valid_outcome = (item["observed"], item["reason"]) == (
                    "failed",
                    "network-error",
                )
            else:
                valid_outcome = (
                    (item["observed"], item["reason"]) == ("absent", "not-found")
                    or (
                        item["observed"] == "failed"
                        and item["reason"]
                        in {"permission-error", "os-error", "timeout", "nonzero-exit"}
                    )
                )
            if not valid_outcome:
                raise ClosedEvidenceError("probe-outcome-invalid")
        if len(_canonical({"probes": probes})) > 64 * 1024:
            raise ClosedEvidenceError("probe-evidence-oversized")
        _reject_sensitive_surface(record)
    except ClosedEvidenceError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        raise ClosedEvidenceError("evidence-invalid") from error


def test_closed_parser_accepts_the_complete_passing_fixture() -> None:
    record, authority = _passing_record()

    _validate_passing_evidence(
        record, instance="aifactory-stage1-fixture", authority=authority
    )


def test_owner_private_reader_authenticates_digest_and_canonical_bytes(tmp_path: Path) -> None:
    record, _authority = _passing_record()
    evidence = tmp_path / "containment-evidence"
    evidence.mkdir(mode=0o700)
    payload = _canonical(record, newline=True)
    digest = hashlib.sha256(payload[:-1]).hexdigest()
    path = evidence / f"{digest}.json"
    path.write_bytes(payload)
    path.chmod(0o600)

    assert _read_owner_private_evidence(path.resolve(), expected_digest=digest) == record


def test_owner_private_reader_rejects_group_readable_evidence(tmp_path: Path) -> None:
    record, _authority = _passing_record()
    evidence = tmp_path / "containment-evidence"
    evidence.mkdir(mode=0o700)
    payload = _canonical(record, newline=True)
    digest = hashlib.sha256(payload[:-1]).hexdigest()
    path = evidence / f"{digest}.json"
    path.write_bytes(payload)
    path.chmod(0o640)

    with pytest.raises(ClosedEvidenceError, match="evidence-file-unsafe"):
        _read_owner_private_evidence(path.resolve(), expected_digest=digest)


def test_operating_runbook_binds_reviewed_commit_and_checkout_interpreter() -> None:
    operating = (REPO_ROOT / "docs" / "OPERATING.md").read_text(encoding="utf-8")
    section = operating.split(
        "### Gate a disposable Linux validation cell before any model task", 1
    )[1].split("### Provider obligations and inspection", 1)[0]

    assert ': "${ACCEPTED_COMMIT:?set to independently reviewed commit}"' in section
    assert 'ACCEPTED_COMMIT="$(git rev-parse HEAD)"' not in section
    assert 'test "$(git rev-parse HEAD)" = "$ACCEPTED_COMMIT"' in section
    assert 'test -z "$(git status --porcelain)"' in section
    assert "--untracked-files=no" not in section
    fail_fast = section.index("set -euo pipefail")
    checkout = section.index('AIFACTORY_CHECKOUT="$(pwd -P)"')
    accepted = section.index(': "${ACCEPTED_COMMIT:?set to independently reviewed commit}"')
    clean = section.index('test -z "$(git status --porcelain)"')
    build = section.index('WHEEL_DIRECTORY="$(mktemp -d)"')
    create = section.index("software_factory.cli validation-cell create")
    assert fail_fast < checkout < accepted < clean < build < create
    assert 'AIFACTORY_PYTHON="$AIFACTORY_CHECKOUT/.venv/bin/python"' in section
    assert "software_factory.__file__" in section
    assert "software_factory.execution.__file__" in section
    assert '"$AIFACTORY_PYTHON" -m software_factory.cli validation-cell --help' in section
    assert section.count(
        '"$AIFACTORY_PYTHON" -m software_factory.cli validation-cell'
    ) >= 8
    login = section.index("claude auth login --claudeai")
    post_auth_doctor = section.index('POST_AUTH_DOCTOR_RECORD="$OPERATOR_EVIDENCE/')
    import_cell = section.index("software_factory.cli validation-cell import")
    assert login < post_auth_doctor < import_cell
    assert "$MODEL_AUTH_FILE:/root/.claude.json" in section
    assert "post-auth doctor record differs from the pre-auth authority" in section
    assert "factory validation-cell" not in section
    assert "\npython " not in section
    assert "$(python " not in section

    shell_blocks = re.findall(r"```bash\n(.*?)```", section, flags=re.DOTALL)
    create_block = next(
        block for block in shell_blocks if "validation-cell create" in block
    )
    logical_lines = create_block.replace("\\\n", " ").splitlines()
    create_line = next(
        line for line in logical_lines if "validation-cell create" in line
    )
    create_args = shlex.split(create_line)
    expected_artifacts = {
        "--leash-image-archive": "$LEASH_IMAGE_ARCHIVE",
        "--leash-build-record": "$LEASH_BUILD_RECORD",
        "--leash-test-record": "$LEASH_TEST_RECORD",
    }
    for flag, value in expected_artifacts.items():
        assert create_args.count(flag) == 1
        position = create_args.index(flag)
        assert create_args[position + 1] == value
    assert not any(argument.endswith(":latest") for argument in create_args)


def test_integration_marker_is_registered_without_warning_suppression() -> None:
    project = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert '"integration: requires an explicitly selected live validation cell"' in project
    source = Path(__file__).read_text(encoding="utf-8")
    assert "\nimport warnings\n" not in source


@pytest.mark.parametrize(
    "mutation",
    (
        "forbidden-action-succeeded",
        "probe-missing",
        "cleanup-ambiguous",
        "freshness-drift",
        "raw-output-added",
    ),
)
def test_closed_parser_rejects_successful_forbidden_or_ambiguous_evidence(
    mutation: str,
) -> None:
    record, authority = _passing_record()
    candidate = copy.deepcopy(record)
    if mutation == "forbidden-action-succeeded":
        forbidden = candidate["bridge_result"]["probes"][PROBE_IDS.index("network-github")]
        forbidden.update(observed="succeeded", reason="none")
    elif mutation == "probe-missing":
        candidate["bridge_result"]["probes"].pop()
    elif mutation == "cleanup-ambiguous":
        candidate["bridge_result"]["firewall"]["cleanup_verified"] = False
    elif mutation == "freshness-drift":
        candidate["freshness"]["post"] = "c" * 64
    else:
        candidate["bridge_result"]["raw_output"] = "credential=secret"

    with pytest.raises(ClosedEvidenceError):
        _validate_passing_evidence(
            candidate, instance="aifactory-stage1-fixture", authority=authority
        )


@pytest.mark.integration
@pytest.mark.skipif(
    "AIFACTORY_VALIDATION_CELL" not in os.environ,
    reason="set AIFACTORY_VALIDATION_CELL to an already configured disposable cell",
)
def test_real_validation_cell_containment_is_closed_and_fresh() -> None:
    from software_factory.execution.cell import ValidationCell, _instance

    instance = _instance(os.environ["AIFACTORY_VALIDATION_CELL"])
    controller = ValidationCell()
    authority = controller._load(instance)
    assert authority["lifecycle"] == "configured"
    doctor = controller.doctor(instance=instance)
    _validate_pnpm_lifecycle_authority(authority, doctor=doctor)

    result = controller.probe(instance=instance)

    assert set(result) == {"disposition", "record_digest", "summary"}
    assert result["disposition"] == "passed"
    assert result["summary"] == "containment-verified"
    assert DIGEST.fullmatch(result["record_digest"])
    evidence = (
        controller.state_root
        / instance
        / "containment-evidence"
        / f"{result['record_digest']}.json"
    )
    record = _read_owner_private_evidence(
        evidence, expected_digest=result["record_digest"]
    )
    _validate_passing_evidence(record, instance=instance, authority=authority)
    terminal = controller._load(instance)
    assert terminal["lifecycle"] == "stopped"
    assert terminal["retained_lifecycle"] == "configured"
    assert terminal["containment_attempt"] == {
        "attempt_id": terminal["containment_attempt"]["attempt_id"],
        "configured_state_digest": hashlib.sha256(
            _canonical(authority, newline=True)
        ).hexdigest(),
        "stage": "containment",
    }
    assert DIGEST.fullmatch(terminal["containment_attempt"]["attempt_id"])
    assert terminal["containment_result"] == {
        "disposition": "passed",
        "reason": "none",
        "record_digest": result["record_digest"],
    }
    assert terminal["containment_stop"] == {
        "attempted": True,
        "result": "stopped",
    }
