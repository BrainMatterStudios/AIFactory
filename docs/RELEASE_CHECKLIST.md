# Release checklist

Use this checklist for every public package release. Keep command output and
human-review evidence outside the public worktree. No approval for one action
authorizes any later shared-state action.

## Candidate identity

- [ ] Record `<candidate-version>`, the exact candidate `HEAD`, and the exact
  reviewed merge-base before running release gates.
- [ ] Confirm `pyproject.toml`, `software_factory.__version__`, `factory version`,
  `CHANGELOG.md`, the release-note heading, artifact metadata, and the intended
  exact `<candidate-version>` tag all agree.
- [ ] List the capabilities and workflows expected in this candidate. Verify
  each against the implementation rather than carrying forward a prior
  release's feature list.

## Verification and packaging

- [ ] Run selected authority, migration, adversarial, and end-to-end tests;
  record the command, exact pass/skip/fail counts, and candidate `HEAD`.
- [ ] Run the complete documented local CI from a clean environment and record
  every job, exit code, and exact test count.
- [ ] Run the repository-pinned Ruff version and `git diff --check`.
- [ ] Build the source distribution and wheel offline. Inspect filenames,
  package metadata, version, license, included data, and tracked artifact
  contents.
- [ ] Install the wheel without extras in a clean environment. Confirm the core
  imports and `factory version` work with zero third-party runtime dependencies;
  then test each documented optional extra separately where applicable.
- [ ] Exercise current CLI examples, exact Contract and Design approvals,
  Design gate replay, and the documented status exit taxonomy in a temporary
  synthetic repository with external temporary controller state.
- [ ] Exercise the explicit migration preview, capability/analyzer validation,
  new-parent opt-in, sticky-parent behavior, and later-new-parent rollback. Prove
  legacy and Design records remain readable and unmodified.

## Public boundary and provenance

- [ ] Run the current-tree public scanner on the exact candidate and obtain no
  findings: `uv run --extra dev python scripts/check-public-boundary.py`.
- [ ] Run the history scanner from the exact reviewed merge-base through current
  `HEAD` and obtain no findings: `uv run --extra dev python
  scripts/check-public-boundary.py --base-ref <reviewed-merge-base>`.
- [ ] Inspect the exact `<reviewed-merge-base>..HEAD` diff, `git diff --check`,
  diff statistics, name-status output, and complete tracked-file manifest from
  `git ls-files`.
- [ ] Inspect both the current tree and every commit in the candidate history for
  credentials, private facts, generated evidence, unsafe links, unexpected
  binaries, copied expression, and third-party provenance. If unsafe history is
  found, do not push it; construct and re-review sanitized history.
- [ ] Verify every citation, influence, artifact, and dependency has public
  provenance, accurate attribution, compatible licensing, and redistribution
  permission. Conceptual influence must not be presented as vendored code.

## Security, compatibility, and release truth

- [ ] Reconcile the release note, README, adoption guide, operating guide,
  security model, and known limits with the exact candidate behavior.
- [ ] Confirm schema correctness is not claimed as semantic correctness;
  analyzer false positives/negatives, installed-code trust, process and storage
  non-sandbox limits, local approval identity, status observation semantics,
  platform constraints, and the experimental builder warning are explicit.
- [ ] Confirm migration is opt-in per new Contract parent, no auto-migration is
  implied, and rollback does not rewrite sticky in-progress workflows or erase
  prior records.
- [ ] Verify the hosting provider has effective protected production refs with
  required checks and review. A manifest flag or `factory doctor` output is not
  server-side evidence.
- [ ] Confirm examples use obviously synthetic repositories, identities,
  digests, paths, and data.

## Separate shared-state approvals

Stop with a clean, exact local candidate. Obtain and record a fresh explicit
operator approval immediately before each action, re-running relevant gates if
the candidate or reviewed external state changes:

- [ ] Push the exact candidate branch.
- [ ] Create or update the pull request for that exact branch.
- [ ] Merge the reviewed pull request.
- [ ] Create the exact `<candidate-version>` tag.
- [ ] Push that exact tag.
- [ ] Create the GitHub release from that exact tag and artifacts.
- [ ] Publish the exact artifact to a package registry.

Never infer approval to push, open a PR, merge, tag, release, or publish from
approval of any other item.
