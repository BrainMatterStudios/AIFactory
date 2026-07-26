# Cross-cutting correctness rubric

Calibrates the judge across the five always-on dimensions every deliverable is
graded on, whatever the line. Cite the dimension anchor plus the example the work
matches (see `README.md`).

## correctness
**Pass-condition:** the code produces the specified output for every input in its
contract, including the documented edge cases, with no logic error.

### example_id: correctness-pass-01
**Label:** PASS
**Value:** `clamp(v, lo, hi)` returns `lo` for `v < lo`, `hi` for `v > hi`, else `v`.
**Why:** each region of the range is handled and the boundaries are inclusive as documented.

### example_id: correctness-slop-01
**Label:** SLOP
**Value:** `clamp` returns `v` whenever `v > hi` because the upper branch was dropped.
**Why:** an input above the range leaks through unclamped — a logic gap the happy-path check missed.

## completeness
**Pass-condition:** every part of the stated task is addressed; no requirement is silently dropped.

### example_id: completeness-pass-01
**Label:** PASS
**Value:** the change adds the endpoint, its test, and the doc line the work item asked for.
**Why:** all three deliverables named in the work item are present.

### example_id: completeness-slop-01
**Label:** SLOP
**Value:** the endpoint ships without the migration it depends on.
**Why:** a required piece is absent, so the feature cannot run as described.

## tests
**Pass-condition:** there are meaningful tests covering the happy path AND a failure/edge case, not just a smoke check.

### example_id: tests-pass-01
**Label:** PASS
**Value:** a parser test asserts both a well-formed parse and a malformed-input error.
**Why:** behaviour is pinned on both sides of the contract.

### example_id: tests-slop-01
**Label:** SLOP
**Value:** the only test calls the function and asserts it returned something truthy.
**Why:** the assertion does not constrain the output, so a regression would slip through.

## conventions
**Pass-condition:** the change follows the repo's existing patterns, naming, and documented rules.

### example_id: conventions-pass-01
**Label:** PASS
**Value:** a new adapter subclasses the documented base Protocol and registers in the registry.
**Why:** it matches how every other adapter in the tree is wired.

### example_id: conventions-slop-01
**Label:** SLOP
**Value:** a new module re-implements config loading inline instead of using `core/config.py`.
**Why:** it diverges from the one documented config path, adding a second source of truth.

## simplicity
**Pass-condition:** no gratuitous complexity; the solution is the simplest one that satisfies the contract.

### example_id: simplicity-pass-01
**Label:** PASS
**Value:** a three-line dictionary lookup replaces a chain of conditionals.
**Why:** it expresses the same mapping with less surface to maintain.

### example_id: simplicity-slop-01
**Label:** SLOP
**Value:** a caching layer is added for a function called once at startup.
**Why:** the machinery costs more than it saves and obscures the call.
