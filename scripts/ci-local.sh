#!/usr/bin/env bash
# Run exactly what .github/workflows/ci.yml runs, locally, before you push.
#
# This exists because CI once failed on a day nobody changed the code: the
# workflow installed an unpinned linter, a new release widened its default rule
# set, and 144 violations appeared out of nowhere. The tool versions are pinned
# now — but a pin only helps if the thing you run locally uses the same one, so
# this script builds an isolated environment rather than trusting whatever is on
# your PATH.
#
#   ./scripts/ci-local.sh          run every job
#   ./scripts/ci-local.sh lint     run one
#
# Exit code is the number of failed jobs, so it composes with a pre-push hook.
set -uo pipefail

RUFF_VERSION="0.16.0"          # keep in step with ci.yml and pyproject dev extra
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ONLY="${1:-all}"
FAILED=0
BOOTSTRAP_PYTHON="$(command -v python3)"
VENV=""
VENV_ID=""
BARE=""
BARE_ID=""

say()  { printf "\n\033[1m── %s\033[0m\n" "$1"; }
pass() { printf "   \033[32mPASS\033[0m  %s\n" "$1"; }
fail() { printf "   \033[31mFAIL\033[0m  %s\n" "$1"; FAILED=$((FAILED + 1)); }

canonical_temp_parent() {
  "$BOOTSTRAP_PYTHON" - "${TMPDIR:-/tmp}" <<'PY'
import os, stat, sys
raw = sys.argv[1]
parent = os.path.realpath(raw)
if not os.path.isabs(parent) or not os.path.isdir(parent):
    raise SystemExit(1)
uid = os.geteuid()
current = parent
while True:
    info = os.lstat(current)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, uid}:
        raise SystemExit(1)
    writable = info.st_mode & 0o022
    if writable and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
        raise SystemExit(1)
    previous = current
    current = os.path.dirname(current)
    if current == previous:
        break
print(parent)
PY
}

allocate_private_dir() {
  local prefix="$1"
  local parent destination identity
  case "$prefix" in
    software-factory-ci-local|software-factory-ci-bare) ;;
    *) return 1 ;;
  esac
  parent="$(canonical_temp_parent)" || return 1
  destination="$(mktemp -d "$parent/$prefix.XXXXXX")" || return 1
  chmod 700 "$destination" || return 1
  identity="$($BOOTSTRAP_PYTHON - "$destination" "$parent" <<'PY'
import os, stat, sys
path, parent = sys.argv[1:]
info = os.lstat(path)
if os.path.dirname(path) != parent or os.path.islink(path):
    raise SystemExit(1)
if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
    raise SystemExit(1)
if stat.S_IMODE(info.st_mode) != 0o700:
    raise SystemExit(1)
print(f"{info.st_dev}:{info.st_ino}")
PY
)" || return 1
  printf '%s|%s\n' "$destination" "$identity"
}

allocate_toolchain_dir() {
  allocate_private_dir software-factory-ci-local
}

cleanup_toolchain() {
  local candidate="$1"
  local expected="${2:-}"
  local parent
  [ -n "$candidate" ] && [ -n "$expected" ] || return 1
  parent="$(canonical_temp_parent)" || return 1
  "$BOOTSTRAP_PYTHON" - "$candidate" "$parent" "$expected" <<'PY' || return 1
import os, re, stat, sys
path, parent, expected = sys.argv[1:]
if not os.path.isabs(path) or os.path.dirname(path) != parent:
    raise SystemExit(1)
if not re.fullmatch(r"software-factory-ci-(?:local|bare)\.[A-Za-z0-9]+", os.path.basename(path)):
    raise SystemExit(1)
info = os.lstat(path)
if os.path.islink(path) or not stat.S_ISDIR(info.st_mode):
    raise SystemExit(1)
if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
    raise SystemExit(1)
if f"{info.st_dev}:{info.st_ino}" != expected:
    raise SystemExit(1)
PY
  rm -rf -- "$candidate"
}

validate_toolchain_files() {
  local candidate="$1"
  local expected="$2"
  validate_venv_python "$candidate" "$expected" || return 1
  "$BOOTSTRAP_PYTHON" - "$candidate" <<'PY'
import os, stat, sys
root = sys.argv[1]
uid = os.geteuid()
for relative in ("bin/pip", "bin/ruff"):
    path = os.path.join(root, relative)
    info = os.lstat(path)
    if (os.path.islink(path) or info.st_uid != uid or info.st_mode & 0o022
            or not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o100):
        raise SystemExit(1)
PY
}

validate_venv_python() {
  local candidate="$1"
  local expected="$2"
  "$BOOTSTRAP_PYTHON" - "$candidate" "$expected" <<'PY'
import os, stat, sys
root, expected = sys.argv[1:]
uid = os.geteuid()
for relative, kind in (("", "dir"), ("bin", "dir"), ("bin/python", "file")):
    path = os.path.join(root, relative) if relative else root
    info = os.lstat(path)
    if os.path.islink(path) or info.st_uid != uid or info.st_mode & 0o022:
        raise SystemExit(1)
    if kind == "dir" and not stat.S_ISDIR(info.st_mode):
        raise SystemExit(1)
    if kind == "file" and (not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o100):
        raise SystemExit(1)
    if not relative and f"{info.st_dev}:{info.st_ino}" != expected:
        raise SystemExit(1)
PY
}

toolchain_is_healthy() {
  local candidate="$1"
  local expected="$2"
  validate_toolchain_files "$candidate" "$expected" || return 1
  "$candidate/bin/python" -m pip --version >/dev/null 2>&1 || return 1
  [ "$("$candidate/bin/ruff" --version 2>/dev/null)" = "ruff $RUFF_VERSION" ] || return 1
}

create_toolchain() {
  local destination="$1"
  local expected="$2"
  "$BOOTSTRAP_PYTHON" -m venv --copies "$destination" || return 1
  validate_venv_python "$destination" "$expected" || return 1
  "$destination/bin/python" -m pip install -q --disable-pip-version-check -e ".[dev]" >/dev/null || return 1
  validate_venv_python "$destination" "$expected" || return 1
  "$destination/bin/python" -m pip install -q --disable-pip-version-check "ruff==$RUFF_VERSION" >/dev/null || return 1
}

cleanup_all() {
  if [ -n "$BARE" ]; then cleanup_toolchain "$BARE" "$BARE_ID" || true; fi
  if [ -n "$VENV" ]; then cleanup_toolchain "$VENV" "$VENV_ID" || true; fi
}

# Tests source these functions to exercise stale-environment repair without
# installing packages or running jobs. An environment variable cannot skip CI.
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
  return 0
fi

case "$ONLY" in
  all|lint|test|policy|public-boundary|no-hard-deps) ;;
  *) printf "unknown CI job: %s\n" "$ONLY" >&2; exit 2 ;;
esac

cd "$ROOT"
allocation="$(allocate_toolchain_dir)" || exit 1
VENV="${allocation%%|*}"
VENV_ID="${allocation#*|}"
trap cleanup_all EXIT HUP INT TERM
say "creating the pinned toolchain in a private temporary directory"
if ! create_toolchain "$VENV" "$VENV_ID" || ! toolchain_is_healthy "$VENV" "$VENV_ID"; then
  printf "unable to create a valid pinned toolchain\n" >&2
  exit 1
fi

run_job() { [ "$ONLY" = "all" ] || [ "$ONLY" = "$1" ]; }

if run_job lint; then
  say "job: lint"
  if "$VENV/bin/ruff" check software_factory tests; then pass "ruff $RUFF_VERSION"; else fail "ruff"; fi
fi

if run_job test; then
  say "job: test"
  if "$VENV/bin/python" -m pytest -q; then pass "pytest"; else fail "pytest"; fi
  # CI runs the suite on several interpreters and a whole-suite pass can hide an
  # import cycle that only bites a cold single-file run.
  if "$VENV/bin/python" -m pytest -q tests/test_judge_blockers.py >/dev/null 2>&1; then
    pass "single-file run"
  else
    fail "single-file run (likely an import cycle)"
  fi
fi

if run_job policy; then
  say "job: policy"
  if "$VENV/bin/python" -m software_factory.cli personas >/dev/null; then pass "tier policy + persona drift"; else fail "tier policy"; fi
  if "$VENV/bin/python" -m software_factory.cli demo >/dev/null; then pass "offline loop"; else fail "offline loop"; fi
fi

if run_job public-boundary; then
  say "job: public-boundary"
  if "$VENV/bin/python" scripts/check-public-boundary.py; then
    pass "tracked public content"
  else
    fail "public boundary"
  fi
fi

if run_job no-hard-deps; then
  say "job: no-hard-deps"
  # The core advertises zero hard third-party dependencies. Prove it in an
  # environment where PyYAML genuinely is not installed.
  bare_allocation="$(allocate_private_dir software-factory-ci-bare)" || exit 1
  BARE="${bare_allocation%%|*}"
  BARE_ID="${bare_allocation#*|}"
  if ! "$BOOTSTRAP_PYTHON" -m venv --copies "$BARE" \
    || ! validate_venv_python "$BARE" "$BARE_ID" \
    || ! "$BARE/bin/python" -m pip install -q --disable-pip-version-check . >/dev/null 2>&1 \
    || ! validate_venv_python "$BARE" "$BARE_ID"; then
    fail "bare toolchain creation"
  elif "$BARE/bin/python" - <<'PY'
import importlib.util, sys
if importlib.util.find_spec("yaml") is not None:
    sys.exit("PyYAML is present; this job must run bare")
from software_factory.core.orchestrate import classify_tier, combine   # noqa: F401
from software_factory.loop.verify import scan_logs                     # noqa: F401
from software_factory.loop.harvester import harvest                    # noqa: F401
PY
  then pass "core imports with no third-party deps"; else fail "core has a hidden dependency"; fi
  cleanup_toolchain "$BARE" "$BARE_ID" || fail "bare toolchain cleanup"
  BARE=""
  BARE_ID=""
fi

echo
if [ "$FAILED" -eq 0 ]; then
  printf "\033[32mselected jobs passed\033[0m\n"
else
  printf "\033[31m%s job(s) failed — do not push\033[0m\n" "$FAILED"
fi
exit "$FAILED"
