from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


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
