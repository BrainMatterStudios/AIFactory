"""Real-Git and adversarial tests for rollbackable local build artifacts."""

from __future__ import annotations

import fcntl
import hashlib
import importlib
import json
import os
import re
import stat
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from software_factory.build.local_artifacts import local_artifact_policy_sha256
from software_factory.build.operational_evidence import (
    OPERATIONAL_EVIDENCE_SCHEMA_VERSION,
    EvidenceObservation,
    EvidenceReference,
    OperationalDisposition,
    OperationalEvidence,
    operational_evidence_json_bytes,
    operational_evidence_sha256,
)
from software_factory.build.workspace import (
    GitWorktree,
    LocalGitArtifactInventory,
    LocalGitArtifactPayload,
)
from software_factory.core.contracts import canonical_json_bytes


def _git(cwd: Path, *arguments: str, input: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        input=input,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    return result.stdout


def _repository(
    tmp_path: Path, *, object_format: str = "sha1"
) -> tuple[Path, GitWorktree, str, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(
        repository,
        "init",
        "-q",
        f"--object-format={object_format}",
        "-b",
        "develop",
    )
    _git(repository, "config", "user.email", "factory@example.invalid")
    _git(repository, "config", "user.name", "Factory Test")
    _git(repository, "config", "core.quotePath", "true")
    (repository / "README.md").write_text("base\n", encoding="utf-8")
    _git(repository, "add", "README.md")
    _git(repository, "commit", "-q", "-m", "initial base")
    base_revision = _git(repository, "rev-parse", "HEAD").decode().strip()

    workspace = GitWorktree(
        repo_dir=repository,
        branch="factory/issue-42",
        base="develop",
        verify_cmd="true",
        workspace_root=".worktrees",
    )
    workspace.create()
    worktree = Path(workspace.path)
    (worktree / "contracts").mkdir()
    (worktree / "contracts" / "42.json").write_text(
        '{"approved":true}\n', encoding="utf-8"
    )
    _git(worktree, "add", "contracts/42.json")
    _git(worktree, "commit", "-q", "-m", "contract: accept issue 42")
    (worktree / "reviews").mkdir()
    (worktree / "reviews" / "42.json").write_text(
        '{"verdict":"pass"}\n', encoding="utf-8"
    )
    (worktree / "product.py").write_text("validated = True\n", encoding="utf-8")
    _git(worktree, "add", "reviews/42.json", "product.py")
    _git(worktree, "commit", "-q", "-m", "feat: validated product")
    implementation_revision = workspace.head_revision()
    return repository, workspace, base_revision, implementation_revision


def _evidence(
    base_revision: str,
    implementation_revision: str,
    *,
    product_paths: tuple[str, ...] = ("product.py",),
    controller_roots: tuple[str, ...] = (
        ".factory",
        ".superpowers",
        "contracts",
        "reviews",
    ),
) -> OperationalEvidence:
    return OperationalEvidence(
        schema_version=OPERATIONAL_EVIDENCE_SCHEMA_VERSION,
        repository="example/repository",
        issue="42",
        disposition=OperationalDisposition.COMPLETED_NOT_PROMOTED,
        contract_digest="a" * 64,
        design_digest="b" * 64,
        gate_digest="c" * 64,
        capability_digest="d" * 64,
        base_revision=base_revision,
        implementation_revision=implementation_revision,
        verification_passed=True,
        secret_scan_passed=True,
        remote_mutations_permitted=False,
        artifact_policy_digest=local_artifact_policy_sha256(
            controller_roots=controller_roots,
            implementation_paths=product_paths,
        ),
        references=(
            EvidenceReference(
                kind="test-report",
                digest="e" * 64,
                relative_path="verification/tests.json",
            ),
        ),
        metrics={"changed_files": 3},
        observations=(
            EvidenceObservation(kind="tests", passed=True, redacted_excerpt="passed"),
        ),
    )


def _artifact_module():
    try:
        return importlib.import_module("software_factory.build.local_artifacts")
    except ModuleNotFoundError:
        return None


def _exporter(root: Path):
    module = _artifact_module()
    assert module is not None, "the local artifact exporter has not been implemented"
    return module.LocalArtifactExporter(root)


def _export(tmp_path: Path):
    repository, workspace, base_revision, implementation_revision = _repository(
        tmp_path
    )
    evidence = _evidence(base_revision, implementation_revision)
    result = _exporter(tmp_path / "artifacts").export(
        workspace=workspace,
        base_revision=base_revision,
        implementation_revision=implementation_revision,
        evidence=evidence,
        product_paths=("product.py",),
    )
    return repository, workspace, evidence, result


def _artifact_target(root: Path, evidence: OperationalEvidence) -> Path:
    repository_key = hashlib.sha256(
        json.dumps(
            {"repository": evidence.repository},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return root / repository_key / evidence.issue / operational_evidence_sha256(evidence)


def test_public_artifact_payload_verifier_reauthenticates_git_semantics(tmp_path):
    module = _artifact_module()
    _repository_path, _workspace, _evidence_record, result = _export(tmp_path)
    bundle = (result.directory / "authority.bundle").read_bytes()
    patch = (result.directory / "implementation.patch").read_bytes()

    module.verify_local_artifact_payloads(
        result.manifest,
        authority_bundle=bundle,
        implementation_patch=patch,
    )

    attacker_patch = patch + b"attacker-controlled\n"
    self_consistent_manifest = replace(
        result.manifest,
        implementation_patch_sha256=hashlib.sha256(attacker_patch).hexdigest(),
    )
    with pytest.raises(module.LocalArtifactError):
        module.verify_local_artifact_payloads(
            self_consistent_manifest,
            authority_bundle=bundle,
            implementation_patch=attacker_patch,
        )


def _prepare_artifact_parent(root: Path, evidence: OperationalEvidence) -> Path:
    target = _artifact_target(root, evidence)
    root.mkdir(mode=0o700)
    target.parent.mkdir(parents=True, mode=0o700)
    target.parent.parent.chmod(0o700)
    target.parent.chmod(0o700)
    return target


def _product_mutation_repository(
    tmp_path: Path, mutation: str
) -> tuple[Path, GitWorktree, str, str, str]:
    repository = tmp_path / "mutation-repository"
    repository.mkdir()
    _git(repository, "init", "-q", "-b", "develop")
    _git(repository, "config", "user.email", "factory@example.invalid")
    _git(repository, "config", "user.name", "Factory Test")
    _git(repository, "config", "core.quotePath", "true")
    (repository / "README.md").write_text("base\n", encoding="utf-8")
    if mutation == "delete":
        (repository / "product.py").write_text("remove = True\n", encoding="utf-8")
    elif mutation == "text":
        (repository / "product.py").write_text("before = True\n", encoding="utf-8")
    elif mutation == "binary":
        (repository / "product.bin").write_bytes(b"\0before\xff")
    elif mutation == "executable":
        executable = repository / "product.sh"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o644)
    elif mutation == "quoted":
        (repository / "product café.py").write_text("before = True\n", encoding="utf-8")
    elif mutation == "spaces":
        (repository / "product with spaces.py").write_text(
            "before = True\n", encoding="utf-8"
        )
    elif mutation == "hunk-markers":
        (repository / "product.txt").write_text(
            "heading\n- old comment\ntrailer\n", encoding="utf-8"
        )
    elif mutation == "repository-binary-attribute":
        (repository / ".gitattributes").write_text(
            "product.py binary\n", encoding="utf-8"
        )
        (repository / "product.py").write_text("before = True\n", encoding="utf-8")
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "initial base")
    base_revision = _git(repository, "rev-parse", "HEAD").decode().strip()
    workspace = GitWorktree(
        repo_dir=repository,
        branch=f"factory/{mutation}",
        base="develop",
        verify_cmd="true",
        workspace_root=".worktrees",
    )
    workspace.create()
    worktree = Path(workspace.path)
    if mutation == "delete":
        (worktree / "product.py").unlink()
        product_path = "product.py"
    elif mutation == "symlink":
        (worktree / "product-link").symlink_to("README.md")
        product_path = "product-link"
    elif mutation == "gitlink":
        product_path = "vendor/module"
        _git(
            worktree,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{base_revision},{product_path}",
        )
    elif mutation == "text":
        product_path = "product.py"
        (worktree / product_path).write_text("after = True\n", encoding="utf-8")
    elif mutation == "binary":
        product_path = "product.bin"
        (worktree / product_path).write_bytes(b"\0after\xfe\xff")
    elif mutation == "executable":
        product_path = "product.sh"
        (worktree / product_path).chmod(0o755)
    elif mutation == "quoted":
        product_path = "product café.py"
        (worktree / product_path).write_text("after = True\n", encoding="utf-8")
    elif mutation == "spaces":
        product_path = "product with spaces.py"
        (worktree / product_path).write_text("after = True\n", encoding="utf-8")
    elif mutation == "empty-addition":
        product_path = "empty-product"
        (worktree / product_path).write_bytes(b"")
    elif mutation == "hunk-markers":
        product_path = "product.txt"
        (worktree / product_path).write_text(
            "heading\n+ new token\ntrailer\n", encoding="utf-8"
        )
    elif mutation == "repository-binary-attribute":
        product_path = "product.py"
        (worktree / product_path).write_text("after = True\n", encoding="utf-8")
    else:
        raise AssertionError(f"unknown mutation: {mutation}")
    if mutation != "gitlink":
        _git(worktree, "add", "-A")
    _git(worktree, "commit", "-q", "-m", f"feat: {mutation} product")
    return (
        repository,
        workspace,
        base_revision,
        workspace.head_revision(),
        product_path,
    )


def _gitlink_patch(tmp_path: Path, path: str, target_revision: str) -> bytes:
    repository = tmp_path / "gitlink-patch-repository"
    repository.mkdir()
    _git(repository, "init", "-q", "-b", "main")
    _git(repository, "config", "user.email", "factory@example.invalid")
    _git(repository, "config", "user.name", "Factory Test")
    _git(repository, "commit", "--allow-empty", "-q", "-m", "base")
    base = _git(repository, "rev-parse", "HEAD").decode().strip()
    _git(
        repository,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{target_revision},{path}",
    )
    _git(repository, "commit", "-q", "-m", "add hostile gitlink")
    implementation = _git(repository, "rev-parse", "HEAD").decode().strip()
    return _git(
        repository,
        "--literal-pathspecs",
        "diff",
        "--binary",
        "--full-index",
        "--no-renames",
        base,
        implementation,
        "--",
        path,
    )


def _gitlink_modification_patch(tmp_path: Path, path: str) -> bytes:
    repository = tmp_path / "gitlink-modification-patch-repository"
    repository.mkdir()
    _git(repository, "init", "-q", "-b", "main")
    _git(repository, "config", "user.email", "factory@example.invalid")
    _git(repository, "config", "user.name", "Factory Test")
    _git(repository, "commit", "--allow-empty", "-q", "-m", "first target")
    first_target = _git(repository, "rev-parse", "HEAD").decode().strip()
    _git(repository, "commit", "--allow-empty", "-q", "-m", "second target")
    second_target = _git(repository, "rev-parse", "HEAD").decode().strip()
    _git(
        repository,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{first_target},{path}",
    )
    _git(repository, "commit", "-q", "-m", "add gitlink")
    base = _git(repository, "rev-parse", "HEAD").decode().strip()
    _git(
        repository,
        "update-index",
        "--cacheinfo",
        f"160000,{second_target},{path}",
    )
    _git(repository, "commit", "-q", "-m", "modify gitlink")
    implementation = _git(repository, "rev-parse", "HEAD").decode().strip()
    return _git(
        repository,
        "--literal-pathspecs",
        "diff",
        "--binary",
        "--full-index",
        "--no-renames",
        base,
        implementation,
        "--",
        path,
    )


def _controller_rename_edit_patch(tmp_path: Path) -> bytes:
    repository = tmp_path / "controller-rename-edit-patch-repository"
    repository.mkdir()
    _git(repository, "init", "-q", "-b", "main")
    _git(repository, "config", "user.email", "factory@example.invalid")
    _git(repository, "config", "user.name", "Factory Test")
    (repository / "contracts").mkdir()
    (repository / "contracts" / "42.json").write_text(
        "one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\n", encoding="utf-8"
    )
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "controller base")
    base = _git(repository, "rev-parse", "HEAD").decode().strip()
    _git(repository, "mv", "contracts/42.json", "product.py")
    (repository / "product.py").write_text(
        "one\ntwo\nthree changed\nfour\nfive\nsix\nseven\neight\n",
        encoding="utf-8",
    )
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "rename and edit controller bytes")
    implementation = _git(repository, "rev-parse", "HEAD").decode().strip()
    patch = _git(
        repository,
        "--literal-pathspecs",
        "diff",
        "--binary",
        "--full-index",
        "--find-renames",
        base,
        implementation,
        "--",
    )
    assert b"rename from contracts/42.json\n" in patch
    forbidden = (
        b"similarity index ",
        b"rename from ",
        b"rename to ",
        b"copy from ",
        b"copy to ",
    )
    return b"".join(
        line for line in patch.splitlines(keepends=True) if not line.startswith(forbidden)
    )


def test_real_repository_exports_verified_fetchable_and_projected_artifacts(tmp_path):
    """A local export must replay authority while projecting product bytes only."""
    _repository_dir, _workspace, evidence, result = _export(tmp_path)
    directory = result.directory
    expected_names = {
        "authority.bundle",
        "evidence.json",
        "implementation.patch",
        "manifest.json",
    }

    assert directory.parent.name == evidence.issue
    assert directory.name == operational_evidence_sha256(evidence)
    assert {path.name for path in directory.iterdir()} == expected_names
    assert directory.stat().st_mode & 0o777 == 0o700
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o600 for path in directory.iterdir()
    )
    assert (directory / "evidence.json").read_bytes() == (
        operational_evidence_json_bytes(evidence) + b"\n"
    )

    manifest_bytes = directory.joinpath("manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    assert manifest_bytes == (
        json.dumps(
            manifest,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    assert manifest["trust_domains"]["authority"]["file"] == "authority.bundle"
    assert manifest["trust_domains"]["authority"]["paths"] == [
        "contracts/42.json",
        "product.py",
        "reviews/42.json",
    ]
    assert manifest["trust_domains"]["implementation"]["file"] == (
        "implementation.patch"
    )
    assert manifest["trust_domains"]["implementation"]["paths"] == ["product.py"]
    for name in expected_names - {"manifest.json"}:
        expected_digest = hashlib.sha256(directory.joinpath(name).read_bytes()).hexdigest()
        if name == "authority.bundle":
            observed = manifest["trust_domains"]["authority"]["sha256"]
        elif name == "implementation.patch":
            observed = manifest["trust_domains"]["implementation"]["sha256"]
        else:
            observed = manifest["evidence"]["sha256"]
        assert observed == expected_digest

    recovery = tmp_path / "recovery"
    recovery.mkdir()
    _git(recovery, "init", "-q", "-b", "recovery")
    for revision in (evidence.base_revision, evidence.implementation_revision):
        absent = subprocess.run(
            ["git", "cat-file", "-e", f"{revision}^{{commit}}"],
            cwd=recovery,
            capture_output=True,
            check=False,
        )
        assert absent.returncode != 0
    bundle_ref = f"refs/heads/{evidence.implementation_revision}"
    heads = _git(
        recovery, "bundle", "list-heads", str(directory / "authority.bundle")
    )
    assert heads.splitlines() == [
        f"{evidence.implementation_revision} {bundle_ref}".encode()
    ]
    verified = subprocess.run(
        ["git", "bundle", "verify", str(directory / "authority.bundle")],
        cwd=recovery,
        capture_output=True,
        text=True,
        check=False,
    )
    assert verified.returncode == 0, verified.stderr
    _git(
        recovery,
        "fetch",
        "-q",
        str(directory / "authority.bundle"),
        f"{bundle_ref}:refs/remotes/local-artifact/implementation",
    )
    assert (
        _git(recovery, "rev-parse", "refs/remotes/local-artifact/implementation")
        .decode()
        .strip()
        == evidence.implementation_revision
    )
    assert (
        _git(recovery, "rev-parse", f"{evidence.base_revision}^{{commit}}")
        .decode()
        .strip()
        == evidence.base_revision
    )
    _git(recovery, "checkout", "-q", "--detach", evidence.implementation_revision)
    assert _git(recovery, "rev-parse", "HEAD").decode().strip() == (
        evidence.implementation_revision
    )
    patch = directory.joinpath("implementation.patch").read_bytes()
    regenerated = _git(
        recovery,
        "-c",
        "core.quotePath=true",
        "-c",
        "diff.algorithm=myers",
        "-c",
        "diff.indentHeuristic=false",
        "-c",
        "diff.context=3",
        "-c",
        "diff.interHunkContext=0",
        "-c",
        "diff.suppressBlankEmpty=false",
        "--literal-pathspecs",
        "diff",
        "--no-color",
        "--no-renames",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        "--no-textconv",
        "--diff-algorithm=myers",
        "--no-indent-heuristic",
        "--unified=3",
        "--inter-hunk-context=0",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        evidence.base_revision,
        evidence.implementation_revision,
        "--",
        "product.py",
    )
    assert regenerated == patch

    candidate = tmp_path / "candidate"
    candidate.mkdir()
    _git(candidate, "init", "-q", "-b", "candidate")
    _git(
        candidate,
        "fetch",
        "-q",
        str(directory / "authority.bundle"),
        f"{bundle_ref}:refs/heads/authority",
    )
    _git(candidate, "checkout", "-q", "-b", "base", evidence.base_revision)
    _git(candidate, "apply", "--check", "-", input=patch)
    _git(candidate, "apply", "-", input=patch)
    assert candidate.joinpath("product.py").read_text(encoding="utf-8") == (
        "validated = True\n"
    )
    assert not candidate.joinpath("contracts/42.json").exists()
    assert not candidate.joinpath("reviews/42.json").exists()


def test_bundle_with_unadvertised_object_is_rejected_and_never_published(
    tmp_path, monkeypatch
):
    """A one-ref bundle cannot smuggle an unreachable secret into recovery state."""
    module = _artifact_module()
    assert module is not None
    _repository_dir, workspace, base, implementation = _repository(tmp_path)
    worktree = Path(workspace.path)
    evidence = _evidence(base, implementation)
    root = tmp_path / "artifacts"
    real_export = workspace.collect_local_git_artifacts
    secret = _git(
        worktree,
        "hash-object",
        "-w",
        "--stdin",
        input=b"unreachable controller secret\n",
    ).strip()
    assert secret not in _git(
        worktree,
        "rev-list",
        "--objects",
        "--no-object-names",
        implementation,
    ).splitlines()

    def smuggle_unadvertised_object(**kwargs):
        payload = real_export(**kwargs)
        reachable = _git(
            worktree,
            "rev-list",
            "--objects",
            "--no-object-names",
            implementation,
        ).splitlines()
        pack = _git(
            worktree,
            "pack-objects",
            "--stdout",
            input=b"\n".join((*reachable, secret)) + b"\n",
        )
        advertised_ref = f"refs/heads/{implementation}"
        bundle = tmp_path / "smuggled-authority.bundle"
        bundle_bytes = (
            b"# v2 git bundle\n"
            + f"{implementation} {advertised_ref}\n\n".encode()
            + pack
        )
        bundle.write_bytes(bundle_bytes)
        verifier = tmp_path / "hostile-bundle-verifier"
        verifier.mkdir()
        _git(verifier, "init", "-q", "-b", "verify")
        assert _git(verifier, "bundle", "list-heads", str(bundle)).splitlines() == [
            f"{implementation} {advertised_ref}".encode()
        ]
        _git(verifier, "bundle", "verify", str(bundle))
        return replace(payload, authority_bundle=bundle_bytes)

    monkeypatch.setattr(
        workspace, "collect_local_git_artifacts", smuggle_unadvertised_object
    )
    with pytest.raises(
        module.LocalArtifactError, match="unadvertised or missing objects"
    ):
        _exporter(root).export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=evidence,
            product_paths=("product.py",),
        )
    assert not _artifact_target(root, evidence).exists()

    monkeypatch.setattr(workspace, "collect_local_git_artifacts", real_export)
    result = _exporter(root).export(
        workspace=workspace,
        base_revision=base,
        implementation_revision=implementation,
        evidence=evidence,
        product_paths=("product.py",),
    )
    recovery = tmp_path / "hidden-object-recovery"
    recovery.mkdir()
    _git(recovery, "init", "-q", "-b", "recovery")
    advertised_ref = f"refs/heads/{implementation}"
    _git(
        recovery,
        "fetch",
        "-q",
        str(result.directory / "authority.bundle"),
        f"{advertised_ref}:refs/heads/authority",
    )
    absent = subprocess.run(
        ["git", "cat-file", "-e", secret.decode("ascii")],
        cwd=recovery,
        capture_output=True,
        check=False,
    )
    assert absent.returncode != 0


def test_verification_git_ignores_inherited_alternate_object_database(
    tmp_path, monkeypatch
):
    """An ambient alternate cannot contaminate scratch or published authority."""
    alternate = tmp_path / "unrelated-alternate"
    alternate.mkdir()
    _git(alternate, "init", "-q", "-b", "unrelated")
    secret = _git(
        alternate,
        "hash-object",
        "-w",
        "--stdin",
        input=b"ambient alternate secret\n",
    ).strip()
    _repository_dir, workspace, base, implementation = _repository(tmp_path)
    monkeypatch.setenv(
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        str(alternate / ".git" / "objects"),
    )

    result = _exporter(tmp_path / "artifacts").export(
        workspace=workspace,
        base_revision=base,
        implementation_revision=implementation,
        evidence=_evidence(base, implementation),
        product_paths=("product.py",),
    )

    monkeypatch.delenv("GIT_ALTERNATE_OBJECT_DIRECTORIES")
    recovery = tmp_path / "alternate-isolation-recovery"
    recovery.mkdir()
    _git(recovery, "init", "-q", "-b", "recovery")
    advertised_ref = f"refs/heads/{implementation}"
    bundle = result.directory / "authority.bundle"
    assert _git(recovery, "bundle", "list-heads", str(bundle)).splitlines() == [
        f"{implementation} {advertised_ref}".encode()
    ]
    _git(
        recovery,
        "fetch",
        "-q",
        str(bundle),
        f"{advertised_ref}:refs/heads/authority",
    )
    reachable = set(
        _git(
            recovery,
            "rev-list",
            "--objects",
            "--no-object-names",
            implementation,
        ).splitlines()
    )
    all_objects = set(
        _git(
            recovery,
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)",
        ).splitlines()
    )
    assert all_objects == reachable
    assert secret not in all_objects


def test_every_controller_git_subprocess_ignores_inherited_trace(
    tmp_path, monkeypatch
):
    """Even direct patch inspection cannot inherit ambient Git instrumentation."""
    module = _artifact_module()
    assert module is not None
    _repository_dir, workspace, base, implementation = _repository(tmp_path)
    evidence = _evidence(base, implementation)
    clean = _exporter(tmp_path / "clean-artifacts").export(
        workspace=workspace,
        base_revision=base,
        implementation_revision=implementation,
        evidence=evidence,
        product_paths=("product.py",),
    )
    patch_bytes = clean.directory.joinpath("implementation.patch").read_bytes()
    bundle_bytes = clean.directory.joinpath("authority.bundle").read_bytes()
    inventory = LocalGitArtifactInventory(
        authority_revisions=clean.manifest.authority_revisions,
        authority_paths=clean.manifest.authority_paths,
        implementation_paths=clean.manifest.implementation_paths,
    )

    class PrebuiltArtifactSource:
        def configure_publication_policy(self, *, remote_mutations_permitted):
            assert remote_mutations_permitted is False

        def attest_local_validation_git_policy(self):
            return True

        def head_revision(self):
            return implementation

        def collect_local_git_artifacts(self, **kwargs):
            assert (kwargs["base_revision"], kwargs["implementation_revision"]) == (
                base,
                implementation,
            )
            return LocalGitArtifactPayload(bundle_bytes, patch_bytes, inventory)

    trace = tmp_path / "attacker-selected-git.trace"
    monkeypatch.setenv("GIT_TRACE", str(trace))
    _exporter(tmp_path / "traced-artifacts").export(
        workspace=PrebuiltArtifactSource(),
        base_revision=base,
        implementation_revision=implementation,
        evidence=evidence,
        product_paths=("product.py",),
    )

    assert not trace.exists()


def test_xdg_global_attributes_cannot_change_controller_patch_identity(
    tmp_path, monkeypatch
):
    """Ambient user attributes cannot change text/binary recovery semantics."""
    _repository_dir, workspace, base, implementation = _repository(tmp_path)
    evidence = _evidence(base, implementation)
    clean = _exporter(tmp_path / "clean-artifacts").export(
        workspace=workspace,
        base_revision=base,
        implementation_revision=implementation,
        evidence=evidence,
        product_paths=("product.py",),
    )
    xdg = tmp_path / "hostile-xdg"
    attributes = xdg / "git" / "attributes"
    attributes.parent.mkdir(parents=True)
    attributes.write_text("*.py binary\n", encoding="utf-8")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))

    hostile = _exporter(tmp_path / "hostile-xdg-artifacts").export(
        workspace=workspace,
        base_revision=base,
        implementation_revision=implementation,
        evidence=evidence,
        product_paths=("product.py",),
    )

    assert clean.directory.joinpath("implementation.patch").read_bytes() == (
        hostile.directory.joinpath("implementation.patch").read_bytes()
    )


def test_repository_quote_path_config_cannot_change_the_published_patch(tmp_path):
    """Repository-local display config cannot become patch identity authority."""
    _repo, workspace, base, implementation, product_path = (
        _product_mutation_repository(tmp_path, "quoted")
    )
    evidence = _evidence(base, implementation, product_paths=(product_path,))
    first = _exporter(tmp_path / "quoted-artifacts").export(
        workspace=workspace,
        base_revision=base,
        implementation_revision=implementation,
        evidence=evidence,
        product_paths=(product_path,),
    )
    _git(Path(workspace.path), "config", "core.quotePath", "false")
    second = _exporter(tmp_path / "raw-unicode-artifacts").export(
        workspace=workspace,
        base_revision=base,
        implementation_revision=implementation,
        evidence=evidence,
        product_paths=(product_path,),
    )

    assert first.directory.joinpath("implementation.patch").read_bytes() == (
        second.directory.joinpath("implementation.patch").read_bytes()
    )


def test_source_patch_content_cannot_override_controller_generation(
    tmp_path, monkeypatch
):
    """A structurally valid source patch is transport input, not public authority."""
    module = _artifact_module()
    assert module is not None
    _repo, workspace, base, implementation = _repository(tmp_path)
    real_export = workspace.collect_local_git_artifacts

    def substitute_valid_product_content(**kwargs):
        payload = real_export(**kwargs)
        source_bytes = payload.implementation_patch
        assert source_bytes.count(b"+validated = True\n") == 1
        hostile = (
            source_bytes.replace(b"+validated = True\n", b"+attacker = True\n")
        )
        assert module.LocalArtifactExporter._patch_paths(hostile) == (
            "product.py",
        )
        return replace(payload, implementation_patch=hostile)

    monkeypatch.setattr(
        workspace, "collect_local_git_artifacts", substitute_valid_product_content
    )
    result = _exporter(tmp_path / "artifacts").export(
        workspace=workspace,
        base_revision=base,
        implementation_revision=implementation,
        evidence=_evidence(base, implementation),
        product_paths=("product.py",),
    )
    published = result.directory.joinpath("implementation.patch").read_bytes()
    assert b"+validated = True\n" in published
    assert b"+attacker = True\n" not in published


def test_mixed_revision_hash_formats_are_rejected_before_head_inspection(tmp_path):
    """A SHA-1 base and SHA-256 implementation cannot name one repository history."""
    module = _artifact_module()
    assert module is not None
    _repo, workspace, base, _implementation = _repository(tmp_path)
    implementation = "f" * 64

    with pytest.raises(module.LocalArtifactError, match=r"hash format|length"):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=_evidence(base, implementation),
            product_paths=("product.py",),
        )


def test_sha256_repository_exports_and_recovers_exact_authority(tmp_path):
    """Scratch verification must use the exact object format of 64-hex revisions."""
    capability = tmp_path / "sha256-capability"
    supported = subprocess.run(
        ["git", "init", "--bare", "--object-format=sha256", "-q", capability],
        capture_output=True,
        check=False,
    )
    if supported.returncode != 0:
        pytest.skip("host Git does not support SHA-256 repositories")
    case = tmp_path / "sha256-case"
    case.mkdir()
    _repo, workspace, base, implementation = _repository(
        case, object_format="sha256"
    )
    assert len(base) == len(implementation) == 64
    evidence = _evidence(base, implementation)
    result = _exporter(tmp_path / "sha256-artifacts").export(
        workspace=workspace,
        base_revision=base,
        implementation_revision=implementation,
        evidence=evidence,
        product_paths=("product.py",),
    )

    recovery = tmp_path / "sha256-recovery"
    recovery.mkdir()
    _git(
        recovery,
        "init",
        "-q",
        "--object-format=sha256",
        "-b",
        "recovery",
    )
    bundle = result.directory / "authority.bundle"
    _git(recovery, "bundle", "verify", str(bundle))
    advertised_ref = f"refs/heads/{implementation}"
    _git(
        recovery,
        "fetch",
        "-q",
        str(bundle),
        f"{advertised_ref}:refs/heads/authority",
    )
    assert _git(recovery, "rev-parse", f"{base}^{{commit}}").decode().strip() == base
    assert _git(recovery, "rev-parse", "refs/heads/authority").decode().strip() == (
        implementation
    )
    _git(recovery, "checkout", "-q", "-b", "base", base)
    _git(
        recovery,
        "apply",
        "-",
        input=result.directory.joinpath("implementation.patch").read_bytes(),
    )
    assert recovery.joinpath("product.py").read_text(encoding="utf-8") == (
        "validated = True\n"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "text",
        "binary",
        "delete",
        "empty-addition",
        "executable",
        "hunk-markers",
        "quoted",
        "repository-binary-attribute",
        "spaces",
        "symlink",
    ],
)
def test_projected_patch_preserves_supported_blob_deltas(tmp_path, mutation):
    """Structural inspection retains ordinary blob, mode, deletion, and link patches."""
    repository, workspace, base, implementation, product_path = (
        _product_mutation_repository(tmp_path, mutation)
    )
    evidence = _evidence(base, implementation, product_paths=(product_path,))
    result = _exporter(tmp_path / "artifacts").export(
        workspace=workspace,
        base_revision=base,
        implementation_revision=implementation,
        evidence=evidence,
        product_paths=(product_path,),
    )
    candidate = tmp_path / "mutation-candidate"
    candidate.mkdir()
    _git(candidate, "init", "-q", "-b", "candidate")
    _git(candidate, "fetch", "-q", str(repository), f"{base}:refs/heads/base")
    _git(candidate, "checkout", "-q", "base")
    _git(
        candidate,
        "apply",
        "-",
        input=result.directory.joinpath("implementation.patch").read_bytes(),
    )

    if mutation == "delete":
        assert not candidate.joinpath(product_path).exists()
    elif mutation == "symlink":
        assert candidate.joinpath(product_path).is_symlink()
        assert os.readlink(candidate / product_path) == "README.md"
    else:
        expected = Path(workspace.path, product_path)
        assert candidate.joinpath(product_path).read_bytes() == expected.read_bytes()
        if mutation == "executable":
            assert stat.S_IMODE(candidate.joinpath(product_path).stat().st_mode) == 0o755
        if mutation == "hunk-markers":
            patch = result.directory.joinpath("implementation.patch").read_bytes()
            assert b"-- old comment\n" in patch
            assert b"++ new token\n" in patch
        if mutation == "repository-binary-attribute":
            patch = result.directory.joinpath("implementation.patch").read_bytes()
            assert b"GIT binary patch\n" in patch


@pytest.mark.parametrize("malleation", ["truncated", "overrun", "malformed"])
def test_structural_parser_rejects_invalid_hunk_counts(tmp_path, malleation):
    """Text hunk counts are structure, not opaque input delegated only to Git."""
    _repo, workspace, base, implementation, product_path = (
        _product_mutation_repository(tmp_path, "hunk-markers")
    )
    patch = _git(
        Path(workspace.path),
        "--literal-pathspecs",
        "diff",
        "--no-renames",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        "--no-textconv",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        base,
        implementation,
        "--",
        product_path,
    )
    lines = patch.splitlines(keepends=True)
    position = next(i for i, line in enumerate(lines) if line.startswith(b"@@ "))
    if malleation == "truncated":
        lines[position] = re.sub(rb"\+[0-9]+(?:,[0-9]+)?", b"+1,99", lines[position])
    elif malleation == "overrun":
        lines[position] = re.sub(rb"-[0-9]+(?:,[0-9]+)?", b"-1,1", lines[position])
    else:
        lines[position] = b"@@ -old +new @@\n"
    module = _artifact_module()
    assert module is not None

    with pytest.raises(module.LocalArtifactError, match=r"hunk|patch|malformed"):
        module.LocalArtifactExporter._structural_patch_paths(b"".join(lines))


def test_honest_git_worktree_rejects_gitlink_deltas(tmp_path):
    """A submodule pointer cannot be represented as a standalone recovery patch."""
    _repo, workspace, base, implementation, product_path = (
        _product_mutation_repository(tmp_path, "gitlink")
    )
    module = _artifact_module()
    assert module is not None

    with pytest.raises(module.LocalArtifactError, match=r"gitlink|submodule"):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=_evidence(
                base,
                implementation,
                product_paths=(product_path,),
            ),
            product_paths=(product_path,),
        )


def test_independent_raw_tree_inventory_rejects_gitlink_modes(tmp_path):
    """Fetched-tree mode authority rejects gitlinks independently of patch headers."""
    _repo, workspace, base, implementation, product_path = (
        _product_mutation_repository(tmp_path, "gitlink")
    )
    raw = _git(
        Path(workspace.path),
        "--literal-pathspecs",
        "diff",
        "--raw",
        "-z",
        "--full-index",
        "--no-renames",
        base,
        implementation,
        "--",
        product_path,
    )
    module = _artifact_module()
    assert module is not None

    with pytest.raises(module.LocalArtifactError, match=r"gitlink|submodule"):
        module.LocalArtifactExporter._raw_diff_paths(
            raw, approved_paths=(product_path,)
        )


@pytest.mark.parametrize("operation", ["rename", "copy"])
def test_honest_git_worktree_rejects_controller_source_move_to_product(
    tmp_path, operation
):
    """Destination-only policy cannot launder bytes from controller-owned history."""
    repository = tmp_path / "controller-move-repository"
    repository.mkdir()
    _git(repository, "init", "-q", "-b", "develop")
    _git(repository, "config", "user.email", "factory@example.invalid")
    _git(repository, "config", "user.name", "Factory Test")
    (repository / "contracts").mkdir()
    source = repository / "contracts" / "42.json"
    source.write_text("controller authority bytes\n", encoding="utf-8")
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "contract authority")
    base = _git(repository, "rev-parse", "HEAD").decode().strip()
    workspace = GitWorktree(
        repo_dir=repository,
        branch=f"factory/controller-{operation}",
        base="develop",
        verify_cmd="true",
        workspace_root=".worktrees",
    )
    workspace.create()
    worktree = Path(workspace.path)
    if operation == "rename":
        _git(worktree, "mv", "contracts/42.json", "product.py")
    else:
        (worktree / "product.py").write_bytes(
            (worktree / "contracts" / "42.json").read_bytes()
        )
        _git(worktree, "add", "product.py")
    _git(worktree, "commit", "-q", "-m", f"feat: {operation} controller bytes")
    implementation = workspace.head_revision()
    module = _artifact_module()
    assert module is not None

    with pytest.raises(module.LocalArtifactError, match=r"controller|rename|copy"):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=_evidence(base, implementation),
            product_paths=("product.py",),
        )


@pytest.mark.parametrize("operation", ["rename", "copy"])
def test_honest_git_worktree_rejects_custom_controller_source_move_to_product(
    tmp_path, operation
):
    repository = tmp_path / "custom-controller-move-repository"
    repository.mkdir()
    _git(repository, "init", "-q", "-b", "develop")
    _git(repository, "config", "user.email", "factory@example.invalid")
    _git(repository, "config", "user.name", "Factory Test")
    (repository / "authority").mkdir()
    source = repository / "authority" / "42.json"
    source.write_text("custom controller authority bytes\n", encoding="utf-8")
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "custom contract authority")
    base = _git(repository, "rev-parse", "HEAD").decode().strip()
    workspace = GitWorktree(
        repo_dir=repository,
        branch=f"factory/custom-controller-{operation}",
        base="develop",
        verify_cmd="true",
        workspace_root=".worktrees",
    )
    workspace.create()
    worktree = Path(workspace.path)
    if operation == "rename":
        _git(worktree, "mv", "authority/42.json", "product.py")
    else:
        (worktree / "product.py").write_bytes(
            (worktree / "authority" / "42.json").read_bytes()
        )
        _git(worktree, "add", "product.py")
    _git(worktree, "commit", "-q", "-m", f"feat: {operation} custom authority")
    implementation = workspace.head_revision()
    module = _artifact_module()
    assert module is not None

    with pytest.raises(module.LocalArtifactError, match=r"controller|rename|copy"):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=_evidence(
                base,
                implementation,
                controller_roots=(".factory", ".superpowers", "authority", "reviews"),
            ),
            product_paths=("product.py",),
            controller_roots=(".factory", ".superpowers", "authority", "reviews"),
        )


def test_export_accepts_custom_controller_change_beside_exact_product_change(tmp_path):
    repository = tmp_path / "custom-controller-repository"
    repository.mkdir()
    _git(repository, "init", "-q", "-b", "develop")
    _git(repository, "config", "user.email", "factory@example.invalid")
    _git(repository, "config", "user.name", "Factory Test")
    (repository / "authority").mkdir()
    (repository / "authority" / "42.json").write_text("before\n", encoding="utf-8")
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "custom controller base")
    base = _git(repository, "rev-parse", "HEAD").decode().strip()
    workspace = GitWorktree(
        repo_dir=repository,
        branch="factory/custom-controller-change",
        base="develop",
        verify_cmd="true",
        workspace_root=".worktrees",
    )
    workspace.create()
    worktree = Path(workspace.path)
    (worktree / "authority" / "42.json").write_text("after\n", encoding="utf-8")
    (worktree / "product.py").write_text("validated = True\n", encoding="utf-8")
    implementation = workspace.commit("feat: product with custom authority")

    result = _exporter(tmp_path / "artifacts").export(
        workspace=workspace,
        base_revision=base,
        implementation_revision=implementation,
        evidence=_evidence(
            base,
            implementation,
            controller_roots=(".factory", ".superpowers", "authority", "reviews"),
        ),
        product_paths=("product.py",),
        controller_roots=(".factory", ".superpowers", "authority", "reviews"),
    )

    assert result.manifest.authority_paths == ("authority/42.json", "product.py")
    assert result.manifest.implementation_paths == ("product.py",)
    assert result.manifest.controller_roots == (
        ".factory",
        ".superpowers",
        "authority",
        "reviews",
    )
    module = _artifact_module()
    assert module is not None
    module.verify_local_artifact_payloads(
        result.manifest,
        authority_bundle=result.directory.joinpath("authority.bundle").read_bytes(),
        implementation_patch=result.directory.joinpath(
            "implementation.patch"
        ).read_bytes(),
    )


def test_export_rejects_unclassified_authority_path_outside_product_policy(tmp_path):
    repository, workspace, base, _implementation = _repository(tmp_path)
    worktree = Path(workspace.path)
    (worktree / "outside.py").write_text("outside = True\n", encoding="utf-8")
    implementation = workspace.commit("feat: add unapproved path")
    module = _artifact_module()
    assert module is not None

    with pytest.raises(module.LocalArtifactError, match=r"authority|policy|path"):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=_evidence(base, implementation),
            product_paths=("product.py",),
        )


def test_in_root_rename_exports_both_endpoints_and_removes_old_path(tmp_path):
    repository = tmp_path / "product-rename-repository"
    repository.mkdir()
    _git(repository, "init", "-q", "-b", "develop")
    _git(repository, "config", "user.email", "factory@example.invalid")
    _git(repository, "config", "user.name", "Factory Test")
    (repository / "src").mkdir()
    (repository / "src" / "old.py").write_text("value = 1\n", encoding="utf-8")
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "product base")
    base = _git(repository, "rev-parse", "HEAD").decode().strip()
    workspace = GitWorktree(
        repo_dir=repository,
        branch="factory/product-rename",
        base="develop",
        verify_cmd="true",
        workspace_root=".worktrees",
    )
    workspace.create()
    worktree = Path(workspace.path)
    _git(worktree, "mv", "src/old.py", "src/new.py")
    implementation = workspace.commit("feat: rename product")

    result = _exporter(tmp_path / "artifacts").export(
        workspace=workspace,
        base_revision=base,
        implementation_revision=implementation,
        evidence=_evidence(
            base,
            implementation,
            product_paths=("src/new.py", "src/old.py"),
        ),
        product_paths=("src/new.py", "src/old.py"),
    )

    assert result.manifest.implementation_paths == ("src/new.py", "src/old.py")
    patch = result.directory.joinpath("implementation.patch").read_bytes()
    candidate = tmp_path / "rename-candidate"
    candidate.mkdir()
    _git(candidate, "init", "-q", "-b", "candidate")
    bundle_ref = f"refs/heads/{implementation}"
    _git(
        candidate,
        "fetch",
        "-q",
        str(result.directory / "authority.bundle"),
        f"{bundle_ref}:refs/heads/authority",
    )
    _git(candidate, "checkout", "-q", "-b", "base", base)
    _git(candidate, "apply", "-", input=patch)
    assert not (candidate / "src" / "old.py").exists()
    assert (candidate / "src" / "new.py").read_text(encoding="utf-8") == "value = 1\n"

    # The public manifest retains the normalized controller policy.  Relabeling
    # one rename endpoint as unexplained authority fails before payload replay.
    module = _artifact_module()
    assert module is not None
    with pytest.raises(module.LocalArtifactError, match=r"provenance|policy"):
        replace(
            result.manifest,
            implementation_paths=("src/new.py",),
        )


def test_approved_same_content_copy_exports_only_changed_destination(tmp_path):
    repository = tmp_path / "product-copy-repository"
    repository.mkdir()
    _git(repository, "init", "-q", "-b", "develop")
    _git(repository, "config", "user.email", "factory@example.invalid")
    _git(repository, "config", "user.name", "Factory Test")
    (repository / "src").mkdir()
    (repository / "src" / "base.py").write_text("value = 1\n", encoding="utf-8")
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "product base")
    base = _git(repository, "rev-parse", "HEAD").decode().strip()
    workspace = GitWorktree(
        repo_dir=repository,
        branch="factory/product-copy",
        base="develop",
        verify_cmd="true",
        workspace_root=".worktrees",
    )
    workspace.create()
    worktree = Path(workspace.path)
    (worktree / "src" / "copy.py").write_bytes(
        (worktree / "src" / "base.py").read_bytes()
    )
    implementation = workspace.commit("feat: copy approved product")

    result = _exporter(tmp_path / "artifacts").export(
        workspace=workspace,
        base_revision=base,
        implementation_revision=implementation,
        evidence=_evidence(base, implementation, product_paths=("src/copy.py",)),
        product_paths=("src/copy.py",),
    )

    assert result.manifest.authority_paths == ("src/copy.py",)
    assert result.manifest.implementation_paths == ("src/copy.py",)
    module = _artifact_module()
    assert module is not None
    module.verify_local_artifact_payloads(
        result.manifest,
        authority_bundle=result.directory.joinpath("authority.bundle").read_bytes(),
        implementation_patch=result.directory.joinpath(
            "implementation.patch"
        ).read_bytes(),
    )
    candidate = tmp_path / "copy-candidate"
    candidate.mkdir()
    _git(candidate, "init", "-q", "-b", "candidate")
    bundle_ref = f"refs/heads/{implementation}"
    _git(
        candidate,
        "fetch",
        "-q",
        str(result.directory / "authority.bundle"),
        f"{bundle_ref}:refs/heads/authority",
    )
    _git(candidate, "checkout", "-q", "-b", "base", base)
    _git(
        candidate,
        "apply",
        "-",
        input=result.directory.joinpath("implementation.patch").read_bytes(),
    )
    assert (candidate / "src" / "base.py").read_text(encoding="utf-8") == "value = 1\n"
    assert (candidate / "src" / "copy.py").read_text(encoding="utf-8") == "value = 1\n"


def test_export_rejects_every_preexisting_digest_target(tmp_path):
    """A mutable prior manifest cannot reauthenticate an existing final target."""
    _repository_dir, workspace, evidence, first = _export(tmp_path)
    first.close()

    with pytest.raises(_artifact_module().LocalArtifactError, match="pre-existing"):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=evidence.base_revision,
            implementation_revision=evidence.implementation_revision,
            evidence=evidence,
            product_paths=("product.py",),
        )

    assert first.directory.is_dir()


@pytest.mark.parametrize("tampered_name", ["authority.bundle", "implementation.patch"])
def test_tampered_preexisting_artifacts_cannot_be_reexported(tmp_path, tampered_name):
    """Self-consistent mutable files never become authority on a repeated export."""
    _repository_dir, workspace, evidence, first = _export(tmp_path)
    first.close()
    first.directory.joinpath(tampered_name).write_bytes(b"attacker-controlled\n")

    with pytest.raises(_artifact_module().LocalArtifactError, match="pre-existing"):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=evidence.base_revision,
            implementation_revision=evidence.implementation_revision,
            evidence=evidence,
            product_paths=("product.py",),
        )


def test_preexisting_target_cannot_be_reexported_after_workspace_head_advances(tmp_path):
    """A prior target never bypasses a fresh exact-HEAD check."""
    _repository_dir, workspace, evidence, _first = _export(tmp_path)
    _first.close()
    worktree = Path(workspace.path)
    (worktree / "later.py").write_text("later = True\n", encoding="utf-8")
    _git(worktree, "add", "later.py")
    _git(worktree, "commit", "-q", "-m", "feat: advance after export")

    with pytest.raises(_artifact_module().LocalArtifactError, match="HEAD"):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=evidence.base_revision,
            implementation_revision=evidence.implementation_revision,
            evidence=evidence,
            product_paths=("product.py",),
        )


def test_obsolete_unreleased_manifest_schema_fails_closed(tmp_path):
    module = _artifact_module()
    assert module is not None
    _repository_dir, _workspace, _evidence_record, result = _export(tmp_path)

    with pytest.raises(module.LocalArtifactError, match="schema"):
        replace(result.manifest, schema_version="local-artifact-manifest-v2")


@pytest.mark.parametrize(
    "product_paths",
    [
        (),
        ("product.py", "product.py"),
        ("../product.py",),
        ("./product.py",),
        ("/product.py",),
        ("contracts",),
        ("missing.py",),
        ("product.py", "contracts/42.json"),
    ],
)
def test_product_paths_must_be_a_nonempty_normalized_exact_changed_subset(
    tmp_path, product_paths
):
    """Empty, aliased, broad, absent, or controller-bearing policy cannot export."""
    module = _artifact_module()
    assert module is not None, "the local artifact exporter has not been implemented"
    _repository_dir, workspace, base_revision, implementation_revision = _repository(
        tmp_path
    )
    evidence = _evidence(base_revision, implementation_revision)

    with pytest.raises(module.LocalArtifactError, match=r"product|path|policy"):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=base_revision,
            implementation_revision=implementation_revision,
            evidence=evidence,
            product_paths=product_paths,
        )

    assert not list((tmp_path / "artifacts").rglob("manifest.json"))


def test_export_refuses_a_requested_revision_different_from_workspace_head(tmp_path):
    """A stale authorized SHA cannot export after the checked-out branch advances."""
    module = _artifact_module()
    assert module is not None, "the local artifact exporter has not been implemented"
    _repository_dir, workspace, base_revision, implementation_revision = _repository(
        tmp_path
    )
    worktree = Path(workspace.path)
    (worktree / "later.py").write_text("later = True\n", encoding="utf-8")
    _git(worktree, "add", "later.py")
    _git(worktree, "commit", "-q", "-m", "feat: move head")
    evidence = _evidence(base_revision, implementation_revision)

    with pytest.raises(module.LocalArtifactError, match=r"HEAD|revision"):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=base_revision,
            implementation_revision=implementation_revision,
            evidence=evidence,
            product_paths=("product.py",),
        )


def test_export_refuses_evidence_bound_to_other_exact_revisions(tmp_path):
    """Caller arguments cannot override the exact revisions authenticated by evidence."""
    module = _artifact_module()
    assert module is not None, "the local artifact exporter has not been implemented"
    _repository_dir, workspace, base_revision, implementation_revision = _repository(
        tmp_path
    )
    evidence = _evidence(base_revision, implementation_revision)

    for changed in (
        replace(evidence, base_revision="f" * 40),
        replace(evidence, implementation_revision="f" * 40),
    ):
        with pytest.raises(module.LocalArtifactError, match=r"evidence.*revision"):
            _exporter(tmp_path / "artifacts").export(
                workspace=workspace,
                base_revision=base_revision,
                implementation_revision=implementation_revision,
                evidence=changed,
                product_paths=("product.py",),
            )


def test_export_refuses_unsafe_issue_identity_even_on_a_typed_record(tmp_path):
    """Traversal cannot be smuggled through a post-construction evidence mutation."""
    module = _artifact_module()
    assert module is not None, "the local artifact exporter has not been implemented"
    _repository_dir, workspace, base_revision, implementation_revision = _repository(
        tmp_path
    )
    evidence = _evidence(base_revision, implementation_revision)
    object.__setattr__(evidence, "issue", "..")

    with pytest.raises(module.LocalArtifactError, match="issue"):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=base_revision,
            implementation_revision=implementation_revision,
            evidence=evidence,
            product_paths=("product.py",),
        )


def test_export_refuses_unsafe_repository_identity_even_on_a_typed_record(tmp_path):
    """Repository traversal cannot become a trusted manifest identity."""
    module = _artifact_module()
    assert module is not None, "the local artifact exporter has not been implemented"
    _repository_dir, workspace, base_revision, implementation_revision = _repository(
        tmp_path
    )
    evidence = _evidence(base_revision, implementation_revision)
    object.__setattr__(evidence, "repository", "example/../repository")

    with pytest.raises(module.LocalArtifactError, match="repository"):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=base_revision,
            implementation_revision=implementation_revision,
            evidence=evidence,
            product_paths=("product.py",),
        )


@pytest.mark.parametrize("bad_root", ["symlink", "file", "wrong-mode"])
def test_export_refuses_unsafe_artifact_roots(tmp_path, bad_root):
    """The final root cannot redirect writes or admit another local principal."""
    module = _artifact_module()
    assert module is not None, "the local artifact exporter has not been implemented"
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    root = tmp_path / "artifacts"
    if bad_root == "symlink":
        root.symlink_to(outside, target_is_directory=True)
    elif bad_root == "file":
        root.write_text("not a directory", encoding="utf-8")
    else:
        root.mkdir(mode=0o755)
    _repository_dir, workspace, base_revision, implementation_revision = _repository(
        tmp_path
    )

    with pytest.raises(module.LocalArtifactError, match=r"root|owner|mode|unsafe"):
        _exporter(root).export(
            workspace=workspace,
            base_revision=base_revision,
            implementation_revision=implementation_revision,
            evidence=_evidence(base_revision, implementation_revision),
            product_paths=("product.py",),
        )

    assert not list(outside.iterdir())


@pytest.mark.parametrize("bad_directory", ["symlink", "file", "wrong-mode"])
def test_export_refuses_an_unsafe_controller_directory(tmp_path, bad_directory):
    """A digest-key parent with widened mode cannot host trusted final artifacts."""
    module = _artifact_module()
    assert module is not None, "the local artifact exporter has not been implemented"
    _repository_dir, workspace, base_revision, implementation_revision = _repository(
        tmp_path
    )
    evidence = _evidence(base_revision, implementation_revision)
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    repository_key = hashlib.sha256(
        json.dumps(
            {"repository": evidence.repository},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    unsafe = root / repository_key
    if bad_directory == "symlink":
        outside = tmp_path / "controller-outside"
        outside.mkdir(mode=0o700)
        unsafe.symlink_to(outside, target_is_directory=True)
    elif bad_directory == "file":
        unsafe.write_text("not a directory", encoding="utf-8")
    else:
        unsafe.mkdir(mode=0o755)

    with pytest.raises(module.LocalArtifactError, match=r"owner|mode|unsafe"):
        _exporter(root).export(
            workspace=workspace,
            base_revision=base_revision,
            implementation_revision=implementation_revision,
            evidence=evidence,
            product_paths=("product.py",),
        )


def test_export_refuses_controller_directories_with_a_different_owner(
    tmp_path, monkeypatch
):
    """Mode bits alone cannot authenticate a controller-owned artifact root."""
    module = _artifact_module()
    assert module is not None, "the local artifact exporter has not been implemented"
    _repository_dir, workspace, base_revision, implementation_revision = _repository(
        tmp_path
    )
    real_fstat = module.os.fstat

    def wrong_owner(descriptor):
        result = real_fstat(descriptor)
        values = list(result)
        values[4] = result.st_uid + 1
        return os.stat_result(values)

    monkeypatch.setattr(module.os, "fstat", wrong_owner)

    with pytest.raises(module.LocalArtifactError, match=r"owner|unsafe"):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=base_revision,
            implementation_revision=implementation_revision,
            evidence=_evidence(base_revision, implementation_revision),
            product_paths=("product.py",),
        )


def test_export_refuses_a_preexisting_non_directory_digest_target(tmp_path):
    """Finalization cannot replace a pre-planted digest-keyed leaf."""
    module = _artifact_module()
    assert module is not None, "the local artifact exporter has not been implemented"
    _repository_dir, workspace, base_revision, implementation_revision = _repository(
        tmp_path
    )
    evidence = _evidence(base_revision, implementation_revision)
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    repository_key = hashlib.sha256(
        json.dumps(
            {"repository": evidence.repository},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    target = root / repository_key / evidence.issue / operational_evidence_sha256(evidence)
    target.parent.mkdir(parents=True, mode=0o700)
    target.write_text("attacker", encoding="utf-8")

    with pytest.raises(module.LocalArtifactError, match=r"target|directory|unsafe"):
        _exporter(root).export(
            workspace=workspace,
            base_revision=base_revision,
            implementation_revision=implementation_revision,
            evidence=evidence,
            product_paths=("product.py",),
        )

    assert target.read_text(encoding="utf-8") == "attacker"


def test_stale_persistent_lock_file_is_reusable_after_process_death(tmp_path):
    """Liveness comes from the kernel lock, never from lock-file existence."""
    _repo, workspace, base, implementation = _repository(tmp_path)
    evidence = _evidence(base, implementation)
    root = tmp_path / "artifacts"
    target = _prepare_artifact_parent(root, evidence)
    lock = target.parent / f".{target.name}.lock"
    lock.write_bytes(b"")
    lock.chmod(0o600)

    result = _exporter(root).export(
        workspace=workspace,
        base_revision=base,
        implementation_revision=implementation,
        evidence=evidence,
        product_paths=("product.py",),
    )

    assert result.directory == target
    assert lock.is_file()
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600


@pytest.mark.parametrize("bad_lock", ["symlink", "directory", "wrong-mode"])
def test_persistent_lock_rejects_unsafe_type_link_or_mode(tmp_path, bad_lock):
    """Lock-file existence is harmless only when its identity is controller-safe."""
    module = _artifact_module()
    assert module is not None
    _repo, workspace, base, implementation = _repository(tmp_path)
    evidence = _evidence(base, implementation)
    root = tmp_path / "artifacts"
    target = _prepare_artifact_parent(root, evidence)
    lock = target.parent / f".{target.name}.lock"
    if bad_lock == "symlink":
        outside = tmp_path / "outside-lock"
        outside.write_bytes(b"")
        outside.chmod(0o600)
        lock.symlink_to(outside)
    elif bad_lock == "directory":
        lock.mkdir(mode=0o700)
    else:
        lock.write_bytes(b"")
        lock.chmod(0o644)

    with pytest.raises(module.LocalArtifactError, match=r"lock|unsafe|mode"):
        _exporter(root).export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=evidence,
            product_paths=("product.py",),
        )

    assert not target.exists()


def test_concurrent_advisory_lock_blocks_then_releases_without_cleanup(tmp_path):
    """Closing the holder descriptor makes the persistent lock immediately reusable."""
    module = _artifact_module()
    assert module is not None
    _repo, workspace, base, implementation = _repository(tmp_path)
    evidence = _evidence(base, implementation)
    root = tmp_path / "artifacts"
    target = _prepare_artifact_parent(root, evidence)
    lock = target.parent / f".{target.name}.lock"
    lock.write_bytes(b"")
    lock.chmod(0o600)
    descriptor = os.open(lock, os.O_RDONLY)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(module.LocalArtifactError, match=r"lock|progress"):
            _exporter(root).export(
                workspace=workspace,
                base_revision=base,
                implementation_revision=implementation,
                evidence=evidence,
                product_paths=("product.py",),
            )
    finally:
        os.close(descriptor)

    result = _exporter(root).export(
        workspace=workspace,
        base_revision=base,
        implementation_revision=implementation,
        evidence=evidence,
        product_paths=("product.py",),
    )
    assert result.directory == target


def test_atomic_exclusive_finalization_cannot_replace_a_racing_empty_target(
    tmp_path, monkeypatch
):
    """A destination created at publication wins; completed staging is not moved over it."""
    module = _artifact_module()
    assert module is not None
    _repo, workspace, base, implementation = _repository(tmp_path)
    evidence = _evidence(base, implementation)
    root = tmp_path / "artifacts"
    target = _artifact_target(root, evidence)
    raced = []

    def inject_empty_destination(source_fd, source, destination_fd, destination):
        os.mkdir(destination, 0o700, dir_fd=destination_fd)
        raced.append((source_fd, source, destination_fd, destination))
        raise FileExistsError("injected destination race")

    monkeypatch.setattr(
        module,
        "_rename_directory_exclusive",
        inject_empty_destination,
        raising=False,
    )

    with pytest.raises(module.LocalArtifactError, match=r"target|final|exist|race"):
        _exporter(root).export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=evidence,
            product_paths=("product.py",),
        )

    assert raced
    assert target.is_dir()
    assert list(target.iterdir()) == []
    abandoned = [
        path
        for path in target.parent.iterdir()
        if path.name.startswith(f".{target.name}.") and path.name.endswith(".tmp")
    ]
    assert len(abandoned) == 1
    assert stat.S_IMODE(abandoned[0].stat().st_mode) == 0o700
    assert abandoned[0].joinpath("manifest.json").is_file()


def test_finalization_rejects_digest_directory_swap_before_reopen(
    tmp_path, monkeypatch
):
    """The committed name cannot redirect reads to a self-consistent forgery."""
    module = _artifact_module()
    assert module is not None
    _repo, workspace, base, implementation = _repository(tmp_path)
    evidence = _evidence(base, implementation)
    root = tmp_path / "artifacts"
    real_check = module.LocalArtifactExporter._require_named_directory_identity
    swapped = False

    def swap_then_check(cls, parent, name, descriptor, expected):
        nonlocal swapped
        if not swapped:
            swapped = True
            held = f".{name}.honest"
            os.rename(name, held, src_dir_fd=parent, dst_dir_fd=parent)
            os.mkdir(name, 0o700, dir_fd=parent)
            honest = os.open(held, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent)
            forged = os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent)
            try:
                payloads = {}
                for artifact_name in (
                    "evidence.json",
                    "implementation.patch",
                    "manifest.json",
                ):
                    source = os.open(artifact_name, os.O_RDONLY, dir_fd=honest)
                    try:
                        payloads[artifact_name] = os.read(source, 8 * 1024 * 1024)
                    finally:
                        os.close(source)
                forged_bundle = b"forged invalid bundle\n"
                manifest = json.loads(payloads["manifest.json"])
                manifest["trust_domains"]["authority"]["sha256"] = hashlib.sha256(
                    forged_bundle
                ).hexdigest()
                payloads["authority.bundle"] = forged_bundle
                payloads["manifest.json"] = canonical_json_bytes(manifest) + b"\n"
                for artifact_name, payload in payloads.items():
                    destination = os.open(
                        artifact_name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=forged,
                    )
                    try:
                        os.write(destination, payload)
                    finally:
                        os.close(destination)
            finally:
                os.close(forged)
                os.close(honest)
        real_check(parent, name, descriptor, expected)

    monkeypatch.setattr(
        module.LocalArtifactExporter,
        "_require_named_directory_identity",
        classmethod(swap_then_check),
    )

    with pytest.raises(module.LocalArtifactError, match=r"final directory changed"):
        _exporter(root).export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=evidence,
            product_paths=("product.py",),
        )

    assert swapped


def test_exporter_fails_closed_without_kernel_no_replace_rename(tmp_path, monkeypatch):
    """Ordinary replacing rename is never a fallback for final publication."""
    module = _artifact_module()
    assert module is not None
    monkeypatch.setattr(module, "_EXCLUSIVE_RENAME", None)

    with pytest.raises(module.LocalArtifactError, match=r"secure|exclusive|unavailable"):
        module.LocalArtifactExporter((tmp_path / "artifacts").resolve())


def test_unsafe_semantic_scratch_cleanup_blocks_publication_and_preserves_scratch(
    tmp_path, monkeypatch
):
    """Cleanup uncertainty preserves private scratch and cannot publish around it."""
    module = _artifact_module()
    assert module is not None
    _repo, workspace, base, implementation = _repository(tmp_path)
    evidence = _evidence(base, implementation)
    root = tmp_path / "artifacts"

    def refuse_cleanup(_cls, _directory):
        raise module.LocalArtifactError("synthetic unsafe scratch cleanup")

    monkeypatch.setattr(
        module.LocalArtifactExporter,
        "_remove_scratch_contents",
        classmethod(refuse_cleanup),
    )

    with pytest.raises(module.LocalArtifactError, match=r"scratch|cleanup"):
        _exporter(root).export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=evidence,
            product_paths=("product.py",),
        )

    assert not _artifact_target(root, evidence).exists()
    preserved = list(root.rglob(".semantic-verification.*.tmp"))
    assert len(preserved) == 1
    assert stat.S_IMODE(preserved[0].stat().st_mode) == 0o700


def test_bundle_command_failure_leaves_no_final_artifact(tmp_path, monkeypatch):
    """A failed Git bundle cannot leave a manifest-authenticated partial export."""
    module = _artifact_module()
    assert module is not None, "the local artifact exporter has not been implemented"
    _repository_dir, workspace, base_revision, implementation_revision = _repository(
        tmp_path
    )
    real_git = workspace._git

    def fail_bundle(*arguments, cwd=None):
        if arguments[:2] == ("bundle", "create"):
            return subprocess.CompletedProcess(
                ["git", *arguments], 1, stdout="", stderr="synthetic bundle failure"
            )
        return real_git(*arguments, cwd=cwd)

    monkeypatch.setattr(workspace, "_git", fail_bundle)
    root = tmp_path / "artifacts"
    with pytest.raises(module.LocalArtifactError, match="bundle"):
        _exporter(root).export(
            workspace=workspace,
            base_revision=base_revision,
            implementation_revision=implementation_revision,
            evidence=_evidence(base_revision, implementation_revision),
            product_paths=("product.py",),
        )

    assert not list(root.rglob("manifest.json"))
    assert _git(Path(workspace.path), "branch", "--list", implementation_revision) == b""


def test_source_cannot_widen_returned_inventory(tmp_path, monkeypatch):
    """A bridge-reported path set cannot override controller path authority."""
    module = _artifact_module()
    assert module is not None, "the local artifact exporter has not been implemented"
    _repository_dir, workspace, base_revision, implementation_revision = _repository(
        tmp_path
    )
    real_export = workspace.collect_local_git_artifacts

    def widen_inventory(**kwargs):
        payload = real_export(**kwargs)
        return replace(
            payload,
            inventory=replace(
                payload.inventory,
                implementation_paths=("contracts/42.json", "product.py"),
            ),
        )

    monkeypatch.setattr(workspace, "collect_local_git_artifacts", widen_inventory)
    root = tmp_path / "artifacts"

    with pytest.raises(module.LocalArtifactError, match=r"patch paths|product policy"):
        _exporter(root).export(
            workspace=workspace,
            base_revision=base_revision,
            implementation_revision=implementation_revision,
            evidence=_evidence(base_revision, implementation_revision),
            product_paths=("product.py",),
        )

    assert not list(root.rglob("manifest.json"))


def test_source_cannot_widen_returned_patch_paths(tmp_path, monkeypatch):
    """The exporter, not the source bridge, owns final product-path authority."""
    module = _artifact_module()
    assert module is not None, "the local artifact exporter has not been implemented"
    _repository_dir, workspace, base_revision, implementation_revision = _repository(
        tmp_path
    )
    real_export = workspace.collect_local_git_artifacts

    def widen_patch(**kwargs):
        payload = real_export(**kwargs)
        base = kwargs["base_revision"]
        implementation = kwargs["implementation_revision"]
        widened = subprocess.run(
            [
                "git",
                "--literal-pathspecs",
                "diff",
                "--binary",
                "--full-index",
                base,
                implementation,
                "--",
                "product.py",
                "contracts/42.json",
            ],
            cwd=workspace.path,
            capture_output=True,
            check=True,
        ).stdout
        return replace(payload, implementation_patch=widened)

    monkeypatch.setattr(workspace, "collect_local_git_artifacts", widen_patch)
    root = tmp_path / "artifacts"

    with pytest.raises(module.LocalArtifactError, match=r"patch.*paths|approved.*policy"):
        _exporter(root).export(
            workspace=workspace,
            base_revision=base_revision,
            implementation_revision=implementation_revision,
            evidence=_evidence(base_revision, implementation_revision),
            product_paths=("product.py",),
        )

    assert not list(root.rglob("manifest.json"))


@pytest.mark.parametrize(
    "malleation",
    [
        "mismatched-diff-endpoint",
        "mismatched-content-endpoint",
        "inappropriate-dev-null",
        "missing-content-endpoint",
        "duplicate-index",
        "unparseable-quoted-path",
        "missing-mode-header",
        "unsupported-mode",
    ],
)
def test_hostile_patch_structural_malleations_fail_closed(
    tmp_path, monkeypatch, malleation
):
    """Every record endpoint and mode comes from one canonical no-renames grammar."""
    module = _artifact_module()
    assert module is not None
    _repo, workspace, base, implementation = _repository(tmp_path)
    real_export = workspace.collect_local_git_artifacts

    def substitute_malleated_structure(**kwargs):
        payload = real_export(**kwargs)
        lines = payload.implementation_patch.splitlines(keepends=True)
        if malleation == "mismatched-diff-endpoint":
            lines[0] = b"diff --git a/product.py b/other.py\n"
        elif malleation == "mismatched-content-endpoint":
            position = next(i for i, line in enumerate(lines) if line.startswith(b"+++ "))
            lines[position] = b"+++ b/other.py\n"
        elif malleation == "inappropriate-dev-null":
            position = next(i for i, line in enumerate(lines) if line.startswith(b"+++ "))
            lines[position] = b"+++ /dev/null\n"
        elif malleation == "missing-content-endpoint":
            position = next(i for i, line in enumerate(lines) if line.startswith(b"+++ "))
            del lines[position]
        elif malleation == "duplicate-index":
            position = next(i for i, line in enumerate(lines) if line.startswith(b"index "))
            lines.insert(position + 1, lines[position])
        elif malleation == "unparseable-quoted-path":
            lines[0] = b'diff --git "a/product\\q.py" "b/product\\q.py"\n'
        elif malleation == "missing-mode-header":
            position = next(
                i for i, line in enumerate(lines) if line.startswith(b"new file mode")
            )
            del lines[position]
        else:
            position = next(
                i for i, line in enumerate(lines) if line.startswith(b"new file mode")
            )
            lines[position] = b"new file mode 100664\n"
        return replace(payload, implementation_patch=b"".join(lines))

    monkeypatch.setattr(
        workspace, "collect_local_git_artifacts", substitute_malleated_structure
    )

    with pytest.raises(
        module.LocalArtifactError,
        match=r"patch|path|endpoint|mode|structure|canonical",
    ):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=_evidence(base, implementation),
            product_paths=("product.py",),
        )


@pytest.mark.parametrize("operation", ["rename", "copy"])
def test_hostile_bridge_cannot_move_controller_content_to_an_approved_destination(
    tmp_path, monkeypatch, operation
):
    """Rename/copy metadata must expose or reject its controller-only source."""
    module = _artifact_module()
    assert module is not None
    _repo, workspace, base, implementation = _repository(tmp_path)
    real_export = workspace.collect_local_git_artifacts

    def substitute_metadata_patch(**kwargs):
        payload = real_export(**kwargs)
        metadata = (
            b"diff --git a/contracts/42.json b/product.py\n"
            b"similarity index 100%\n"
            + f"{operation} from contracts/42.json\n".encode()
            + f"{operation} to product.py\n".encode()
        )
        return replace(payload, implementation_patch=metadata)

    monkeypatch.setattr(
        workspace, "collect_local_git_artifacts", substitute_metadata_patch
    )

    with pytest.raises(module.LocalArtifactError, match=r"rename|copy|patch"):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=_evidence(base, implementation),
            product_paths=("product.py",),
        )


def test_hostile_bridge_cannot_hide_an_edited_controller_rename(tmp_path, monkeypatch):
    """Stripping optional rename hints cannot hide mismatched structural endpoints."""
    module = _artifact_module()
    assert module is not None
    _repo, workspace, base, implementation = _repository(tmp_path)
    real_export = workspace.collect_local_git_artifacts

    def substitute_stripped_rename(**kwargs):
        payload = real_export(**kwargs)
        stripped = _controller_rename_edit_patch(tmp_path)
        inspected = subprocess.run(
            ["git", "apply", "--numstat", "-z"],
            input=stripped,
            capture_output=True,
            check=False,
        )
        assert inspected.returncode == 0
        assert inspected.stdout.endswith(b"product.py\0")
        return replace(payload, implementation_patch=stripped)

    monkeypatch.setattr(
        workspace, "collect_local_git_artifacts", substitute_stripped_rename
    )

    with pytest.raises(
        module.LocalArtifactError, match=r"controller|endpoint|structure|patch|path"
    ):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=_evidence(base, implementation),
            product_paths=("product.py",),
        )


def test_hostile_bridge_cannot_emit_a_gitlink_patch(tmp_path, monkeypatch):
    """Independent patch inspection rejects mode 160000 from any source bridge."""
    module = _artifact_module()
    assert module is not None
    _repo, workspace, base, implementation = _repository(tmp_path)
    real_export = workspace.collect_local_git_artifacts

    def substitute_gitlink(**kwargs):
        payload = real_export(**kwargs)
        return replace(
            payload,
            implementation_patch=_gitlink_patch(tmp_path, "product.py", base),
        )

    monkeypatch.setattr(workspace, "collect_local_git_artifacts", substitute_gitlink)

    with pytest.raises(module.LocalArtifactError, match=r"gitlink|submodule|160000"):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=_evidence(base, implementation),
            product_paths=("product.py",),
        )


@pytest.mark.parametrize(
    "malleation", ["uppercase-hashes", "extra-mode-whitespace", "missing-index-mode"]
)
def test_hostile_gitlink_mode_malleations_fail_closed(
    tmp_path, monkeypatch, malleation
):
    """Gitlink rejection comes from canonical mode structure, not a brittle regex."""
    module = _artifact_module()
    assert module is not None
    _repo, workspace, base, implementation = _repository(tmp_path)
    real_export = workspace.collect_local_git_artifacts

    def substitute_malleated_gitlink(**kwargs):
        payload = real_export(**kwargs)
        original = _gitlink_modification_patch(tmp_path, "product.py")
        lines = original.splitlines(keepends=True)
        index = next(position for position, line in enumerate(lines) if line.startswith(b"index "))
        prefix, hashes, mode = lines[index].rstrip(b"\n").split(b" ")
        if malleation == "uppercase-hashes":
            lines[index] = b" ".join((prefix, hashes.upper(), mode)) + b"\n"
        elif malleation == "extra-mode-whitespace":
            lines[index] = b" ".join((prefix, hashes, b"", mode)) + b"\n"
        else:
            lines[index] = b" ".join((prefix, hashes)) + b"\n"
        malleated = b"".join(lines)
        inspected = subprocess.run(
            ["git", "apply", "--numstat", "-z"],
            input=malleated,
            capture_output=True,
            check=False,
        )
        assert inspected.returncode == 0
        return replace(payload, implementation_patch=malleated)

    monkeypatch.setattr(
        workspace, "collect_local_git_artifacts", substitute_malleated_gitlink
    )

    with pytest.raises(
        module.LocalArtifactError, match=r"gitlink|mode|structure|patch|canonical|160000"
    ):
        _exporter(tmp_path / "artifacts").export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=_evidence(base, implementation),
            product_paths=("product.py",),
        )


def test_masked_real_gitlink_patch_is_rejected_before_publication(
    tmp_path, monkeypatch
):
    """Header relabeling cannot turn a gitlink delta into an authenticated blob patch."""
    module = _artifact_module()
    assert module is not None
    _repo, workspace, base, implementation, product_path = (
        _product_mutation_repository(tmp_path, "gitlink")
    )
    worktree = Path(workspace.path)
    root = tmp_path / "artifacts"
    evidence = _evidence(base, implementation, product_paths=(product_path,))

    def substitute_masked_gitlink(**kwargs):
        assert (kwargs["base_revision"], kwargs["implementation_revision"]) == (
            base,
            implementation,
        )
        original = _git(
            worktree,
            "--literal-pathspecs",
            "diff",
            "--no-renames",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            base,
            implementation,
            "--",
            product_path,
        )
        assert original.count(b" 160000\n") == 1
        masked = original.replace(b" 160000\n", b" 100644\n")
        assert module.LocalArtifactExporter._structural_patch_paths(masked) == (
            product_path,
        )
        inspected = subprocess.run(
            ["git", "apply", "--numstat", "-z"],
            input=masked,
            capture_output=True,
            check=False,
        )
        assert inspected.returncode == 0
        export_ref = f"refs/heads/{implementation}"
        bundle_path = tmp_path / "hostile-authority.bundle"
        _git(worktree, "update-ref", export_ref, implementation, "0" * 40)
        try:
            _git(
                worktree,
                "bundle",
                "create",
                str(bundle_path),
                export_ref,
            )
        finally:
            _git(worktree, "update-ref", "-d", export_ref, implementation)
        return LocalGitArtifactPayload(
            authority_bundle=bundle_path.read_bytes(),
            implementation_patch=masked,
            inventory=LocalGitArtifactInventory(
                authority_revisions=(implementation,),
                authority_paths=(product_path,),
                implementation_paths=(product_path,),
            ),
        )

    monkeypatch.setattr(
        workspace, "collect_local_git_artifacts", substitute_masked_gitlink
    )

    with pytest.raises(
        module.LocalArtifactError,
        match=r"semantic|bundle|patch|tree|gitlink|authority",
    ):
        _exporter(root).export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=evidence,
            product_paths=(product_path,),
        )

    assert not _artifact_target(root, evidence).exists()
    assert not list(root.rglob(".semantic-verification.*.tmp"))


def test_all_controller_writes_retry_partial_os_writes(tmp_path, monkeypatch):
    """A legal short write cannot truncate request, evidence, or manifest bytes."""
    module = _artifact_module()
    assert module is not None, "the local artifact exporter has not been implemented"
    real_write = module.os.write

    def short_write(descriptor, payload):
        return real_write(descriptor, payload[: max(1, len(payload) // 2)])

    monkeypatch.setattr(module.os, "write", short_write)

    _repository_dir, _workspace, evidence, result = _export(tmp_path)

    assert result.directory.joinpath("evidence.json").read_bytes() == (
        operational_evidence_json_bytes(evidence) + b"\n"
    )
    json.loads(result.directory.joinpath("manifest.json").read_text(encoding="utf-8"))


def test_zero_length_os_write_fails_closed_without_finalization(tmp_path, monkeypatch):
    """No-progress writes cannot spin forever or publish truncated authority."""
    module = _artifact_module()
    assert module is not None, "the local artifact exporter has not been implemented"

    def no_progress(_directory, _name, _payload):
        raise module.LocalArtifactError("local artifact write made no progress")

    monkeypatch.setattr(
        module.LocalArtifactExporter, "_write_file", staticmethod(no_progress)
    )
    _repository_dir, workspace, base_revision, implementation_revision = _repository(
        tmp_path
    )
    root = tmp_path / "artifacts"

    with pytest.raises(module.LocalArtifactError, match=r"write|written|safely"):
        _exporter(root).export(
            workspace=workspace,
            base_revision=base_revision,
            implementation_revision=implementation_revision,
            evidence=_evidence(base_revision, implementation_revision),
            product_paths=("product.py",),
        )

    assert not list(root.rglob("manifest.json"))


def test_narrow_source_protocol_does_not_expand_the_workspace_interface(tmp_path):
    """Git export authority must remain separately detectable at runtime."""
    module = _artifact_module()
    assert module is not None, "the local artifact exporter has not been implemented"
    _repository_dir, workspace, _base, _implementation = _repository(tmp_path)

    assert isinstance(workspace, module.LocalArtifactSource)
    assert "collect_local_git_artifacts" in GitWorktree.__dict__
    assert "write_git_artifacts" not in GitWorktree.__dict__
    from software_factory.build.workspace import Workspace

    assert "collect_local_git_artifacts" not in Workspace.__dict__
    assert "write_git_artifacts" not in Workspace.__dict__


def test_source_receives_no_controller_artifact_namespace_capability(tmp_path):
    """A source call finishes before the controller artifact namespace exists."""
    module = _artifact_module()
    assert module is not None
    _repository_dir, workspace, base, implementation = _repository(tmp_path)
    artifact_root = tmp_path / "controller-artifacts"

    class NamespaceBlindSource:
        def configure_publication_policy(self, *, remote_mutations_permitted):
            workspace.configure_publication_policy(
                remote_mutations_permitted=remote_mutations_permitted
            )

        def attest_local_validation_git_policy(self):
            return workspace.attest_local_validation_git_policy()

        def head_revision(self):
            return implementation

        def collect_local_git_artifacts(
            self,
            *,
            base_revision,
            implementation_revision,
            product_paths,
            controller_roots,
        ):
            assert not artifact_root.exists()
            assert (base_revision, implementation_revision) == (base, implementation)
            assert product_paths == ("product.py",)
            assert controller_roots == (
                ".factory",
                ".superpowers",
                "contracts",
                "reviews",
            )
            return workspace.collect_local_git_artifacts(
                base_revision=base_revision,
                implementation_revision=implementation_revision,
                product_paths=product_paths,
                controller_roots=controller_roots,
            )

    result = _exporter(artifact_root).export(
        workspace=NamespaceBlindSource(),
        base_revision=base,
        implementation_revision=implementation,
        evidence=_evidence(base, implementation),
        product_paths=("product.py",),
    )
    try:
        result.reauthenticate()
        assert result.directory.is_dir()
    finally:
        result.close()


def test_controller_revalidates_forged_typed_payload_before_creating_namespace(
    tmp_path, monkeypatch
):
    module = _artifact_module()
    assert module is not None
    _repository_dir, workspace, base, implementation = _repository(tmp_path)
    artifact_root = tmp_path / "controller-artifacts"
    real_collect = workspace.collect_local_git_artifacts

    def forged_payload(**kwargs):
        payload = real_collect(**kwargs)
        forged = object.__new__(LocalGitArtifactPayload)
        object.__setattr__(forged, "authority_bundle", payload.authority_bundle)
        object.__setattr__(
            forged, "implementation_patch", bytearray(payload.implementation_patch)
        )
        object.__setattr__(forged, "inventory", payload.inventory)
        return forged

    monkeypatch.setattr(workspace, "collect_local_git_artifacts", forged_payload)

    with pytest.raises(module.LocalArtifactError, match="malformed Git artifact payload"):
        _exporter(artifact_root).export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=_evidence(base, implementation),
            product_paths=("product.py",),
        )
    assert not artifact_root.exists()


def test_controller_revalidates_forged_typed_inventory_before_creating_namespace(
    tmp_path, monkeypatch
):
    module = _artifact_module()
    assert module is not None
    _repository_dir, workspace, base, implementation = _repository(tmp_path)
    artifact_root = tmp_path / "controller-artifacts"
    real_collect = workspace.collect_local_git_artifacts

    def forged_inventory(**kwargs):
        payload = real_collect(**kwargs)
        inventory = object.__new__(LocalGitArtifactInventory)
        object.__setattr__(inventory, "authority_revisions", ())
        object.__setattr__(inventory, "authority_paths", payload.inventory.authority_paths)
        object.__setattr__(
            inventory, "implementation_paths", payload.inventory.implementation_paths
        )
        forged = object.__new__(LocalGitArtifactPayload)
        object.__setattr__(forged, "authority_bundle", payload.authority_bundle)
        object.__setattr__(forged, "implementation_patch", payload.implementation_patch)
        object.__setattr__(forged, "inventory", inventory)
        return forged

    monkeypatch.setattr(workspace, "collect_local_git_artifacts", forged_inventory)

    with pytest.raises(module.LocalArtifactError, match="malformed Git artifact payload"):
        _exporter(artifact_root).export(
            workspace=workspace,
            base_revision=base,
            implementation_revision=implementation,
            evidence=_evidence(base, implementation),
            product_paths=("product.py",),
        )
    assert not artifact_root.exists()


def test_artifact_result_retains_commit_authority_until_closed(tmp_path):
    """Publication returns a live descriptor lease, not an unauthenticated path."""
    _repository_dir, _workspace, _evidence_record, result = _export(tmp_path)
    directory = result.directory
    manifest = result.manifest

    result.reauthenticate()
    assert result._trusted_payloads
    result.close()

    assert result._trusted_payloads == {}
    assert result.directory == directory
    assert result.manifest == manifest
    result.close()
    with pytest.raises(RuntimeError, match="closed"):
        result.reauthenticate()
