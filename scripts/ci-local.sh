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
VENV="${TMPDIR:-/tmp}/software-factory-ci-local"
ONLY="${1:-all}"
FAILED=0

say()  { printf "\n\033[1m── %s\033[0m\n" "$1"; }
pass() { printf "   \033[32mPASS\033[0m  %s\n" "$1"; }
fail() { printf "   \033[31mFAIL\033[0m  %s\n" "$1"; FAILED=$((FAILED + 1)); }

cd "$ROOT"

# One throwaway environment, reused between runs. Delete it to start clean.
if [ ! -x "$VENV/bin/python" ]; then
  say "creating the pinned toolchain in $VENV"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q --disable-pip-version-check -e ".[dev]" >/dev/null
fi
"$VENV/bin/pip" install -q --disable-pip-version-check "ruff==$RUFF_VERSION" >/dev/null

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

if run_job no-hard-deps; then
  say "job: no-hard-deps"
  # The core advertises zero hard third-party dependencies. Prove it in an
  # environment where PyYAML genuinely is not installed.
  BARE="${TMPDIR:-/tmp}/software-factory-ci-bare"
  rm -rf "$BARE" && python3 -m venv "$BARE"
  "$BARE/bin/pip" install -q --disable-pip-version-check . >/dev/null 2>&1
  if "$BARE/bin/python" - <<'PY'
import importlib.util, sys
if importlib.util.find_spec("yaml") is not None:
    sys.exit("PyYAML is present; this job must run bare")
from software_factory.core.orchestrate import classify_tier, combine   # noqa: F401
from software_factory.loop.verify import scan_logs                     # noqa: F401
from software_factory.loop.harvester import harvest                    # noqa: F401
PY
  then pass "core imports with no third-party deps"; else fail "core has a hidden dependency"; fi
  rm -rf "$BARE"
fi

echo
if [ "$FAILED" -eq 0 ]; then
  printf "\033[32mall jobs passed — safe to push\033[0m\n"
else
  printf "\033[31m%s job(s) failed — do not push\033[0m\n" "$FAILED"
fi
exit "$FAILED"
