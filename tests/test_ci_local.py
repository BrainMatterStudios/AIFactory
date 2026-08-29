from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_release_documentation_matches_the_current_public_surface() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    adopting = (REPO_ROOT / "docs" / "ADOPTING.md").read_text(encoding="utf-8")
    operating = (REPO_ROOT / "docs" / "OPERATING.md").read_text(encoding="utf-8")
    known = (REPO_ROOT / "KNOWN_ISSUES.md").read_text(encoding="utf-8")
    security = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    release = (REPO_ROOT / "docs" / "releases" / "0.3.0.md").read_text(encoding="utf-8")

    for command in (
        "factory design validate <file>",
        "factory design gate <file>",
        "factory analyze <adapter>",
        "factory capabilities",
        "factory status [issue]",
        "factory doctor",
    ):
        assert command in readme
        assert command in adopting or command in operating

    combined = "\n".join((readme, adopting, operating, known, security, release))
    normalized_release = " ".join(release.split())
    for required_claim in (
        "ordinary current macOS APFS",
        "installed analyzers are trusted code",
        "transient or external side effects",
        'linearizable "as observed"',
        "not a cryptographic signature",
        "not an OS sandbox",
    ):
        assert required_claim.lower() in normalized_release.lower()

    for stale_claim in (
        "**Status:** 0.2.0",
        "0.2 release-candidate note",
        "There is no separate general design gate",
        "Version 0.2 separates three writable surfaces",
    ):
        assert stale_claim not in combined


def test_release_documentation_local_links_resolve() -> None:
    documents = (
        REPO_ROOT / "README.md",
        REPO_ROOT / "CHANGELOG.md",
        REPO_ROOT / "KNOWN_ISSUES.md",
        REPO_ROOT / "SECURITY.md",
        REPO_ROOT / "docs" / "ADOPTING.md",
        REPO_ROOT / "docs" / "OPERATING.md",
        REPO_ROOT / "docs" / "RELEASE_CHECKLIST.md",
        REPO_ROOT / "docs" / "releases" / "0.3.0.md",
    )
    pattern = re.compile(r"(?<!!)\[[^]]+\]\(([^)]+)\)")

    for document in documents:
        for target in pattern.findall(document.read_text(encoding="utf-8")):
            path = target.split("#", 1)[0]
            if not path or "://" in path or path.startswith("mailto:"):
                continue
            assert (document.parent / path).resolve().exists(), (document, target)


def test_core_release_keeps_zero_hard_dependencies() -> None:
    project = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project_section = project.split("[project]", 1)[1].split("[project.optional-dependencies]", 1)[0]

    assert re.search(r"(?m)^dependencies = \[\]$", project_section)


def _source_script(command: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/bash", "-c", command, "test", str(REPO_ROOT), str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_private_toolchain_does_not_execute_preplanted_predictable_binary(
    tmp_path: Path,
) -> None:
    old_cache = tmp_path / "software-factory-ci-local" / "bin"
    old_cache.mkdir(parents=True)
    marker = tmp_path / "executed"
    fake = old_cache / "python"
    fake.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 0\n", encoding="utf-8")
    fake.chmod(0o755)

    completed = _source_script(
        r'''
set -eu
export TMPDIR="$2"
. "$1/scripts/ci-local.sh"
type allocate_toolchain_dir >/dev/null
type cleanup_toolchain >/dev/null
allocation="$(allocate_toolchain_dir)"
toolchain="${allocation%%|*}"
identity="${allocation#*|}"
case "$toolchain" in "$2"/software-factory-ci-local.*) ;; *) exit 8 ;; esac
test "$("$BOOTSTRAP_PYTHON" -c 'import os, stat, sys; print(f"{stat.S_IMODE(os.lstat(sys.argv[1]).st_mode):o}")' "$toolchain")" = 700
test ! -e "$2/executed"
cleanup_toolchain "$toolchain" "$identity"
test ! -e "$toolchain"
''',
        tmp_path,
    )

    assert completed.returncode == 0, completed.stderr
    assert not marker.exists()


def test_cleanup_refuses_symlink_and_path_traversal_targets(tmp_path: Path) -> None:
    protected = tmp_path / "protected"
    protected.mkdir()
    marker = protected / "marker"
    marker.write_text("keep\n", encoding="utf-8")
    link = tmp_path / "software-factory-ci-local.link"
    os.symlink(protected, link)

    completed = _source_script(
        r'''
set -eu
export TMPDIR="$2"
. "$1/scripts/ci-local.sh"
type cleanup_toolchain >/dev/null
if cleanup_toolchain "$2/software-factory-ci-local.link" "1:1"; then exit 9; fi
if cleanup_toolchain "$2/software-factory-ci-local.fake/../protected" "1:1"; then exit 10; fi
test -e "$2/protected/marker"
''',
        tmp_path,
    )

    assert completed.returncode == 0, completed.stderr
    assert marker.exists()


def test_candidate_python_must_validate_before_it_can_execute(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    fake = tmp_path / "fake-python"
    fake.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    fake.chmod(0o755)

    completed = _source_script(
        r'''
set -eu
export TMPDIR="$2"
. "$1/scripts/ci-local.sh"
type validate_venv_python >/dev/null
allocation="$(allocate_toolchain_dir)"
toolchain="${allocation%%|*}"
identity="${allocation#*|}"
mkdir "$toolchain/bin"
ln -s "$2/fake-python" "$toolchain/bin/python"
if validate_venv_python "$toolchain" "$identity"; then exit 11; fi
test ! -e "$2/executed"
cleanup_toolchain "$toolchain" "$identity"
''',
        tmp_path,
    )

    assert completed.returncode == 0, completed.stderr
    assert not marker.exists()


def test_unknown_job_is_rejected_before_toolchain_creation(tmp_path: Path) -> None:
    completed = subprocess.run(
        ["/bin/bash", str(REPO_ROOT / "scripts" / "ci-local.sh"), "not-a-job"],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "TMPDIR": str(tmp_path)},
    )

    assert completed.returncode != 0
    assert not tuple(tmp_path.glob("software-factory-ci-local.*"))


def test_successful_selected_job_does_not_claim_the_branch_is_safe_to_push(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    bootstrap = fake_bin / "python3"
    bootstrap.write_text(
        r'''#!/bin/sh
if [ "$1" = "-" ]; then
  if [ "$#" -eq 2 ]; then printf '%s\n' "$2"; fi
  if [ "$#" -eq 3 ]; then printf '%s\n' '1:1'; fi
  exit 0
fi
if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then
  destination="$4"
  mkdir -p "$destination/bin"
  printf '%s\n' '#!/bin/sh' 'exit 0' > "$destination/bin/python"
  printf '%s\n' '#!/bin/sh' 'exit 0' > "$destination/bin/pip"
  printf '%s\n' '#!/bin/sh' 'printf "ruff 0.16.0\\n"' > "$destination/bin/ruff"
  chmod 700 "$destination/bin/python" "$destination/bin/pip" "$destination/bin/ruff"
  exit 0
fi
exit 1
''',
        encoding="utf-8",
    )
    bootstrap.chmod(0o755)

    completed = subprocess.run(
        ["/bin/bash", str(REPO_ROOT / "scripts" / "ci-local.sh"), "public-boundary"],
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{fake_bin}:/usr/bin:/bin",
            "TMPDIR": str(tmp_path),
        },
    )

    assert completed.returncode == 0, completed.stderr
    assert "selected jobs passed" in completed.stdout
    assert "safe to push" not in completed.stdout.lower()
