# Release checklist

Use this checklist for every public package release. Record command output and
human review evidence outside the public worktree. No single approval authorizes
a later shared-state action.

## Candidate identity and verification

- [ ] Record the exact candidate commit and the reviewed public base.
- [ ] Confirm `project.version`, `factory version`, the tag name, and
  `CHANGELOG.md` agree.
- [ ] Confirm the candidate contains the implemented `findings_v2` parser,
  authenticated sensor integration, deterministic router, semantic authority
  replay, all-exit scratch cleanup, and focused adversarial tests; record the
  local verification evidence for the exact candidate commit.
- [ ] Run the complete documented local CI from a clean environment and record
  every exit code and test count.
- [ ] Run Ruff with the repository-pinned version and run `git diff --check`.
- [ ] Exercise the zero-hard-dependency install and the real approval path using
  only a temporary synthetic repository and external temporary controller state.

## Public-boundary and provenance review

- [ ] Run the current-tree scanner and obtain no findings:
  `uv run --extra dev python scripts/check-public-boundary.py`.
- [ ] Run the history-range scanner from the reviewed public base and obtain no
  findings: `uv run --extra dev python scripts/check-public-boundary.py
  --base-ref "$REVIEWED_PUBLIC_BASE"`.
- [ ] If the feature history contains prohibited material, do not push it.
  Create sanitized publication history and repeat both scans.
- [ ] Inspect the complete exact diff, `git diff --check`, diff statistics,
  name-status output, and the full `git ls-files` manifest.
- [ ] Confirm no private hosts, accounts, repositories, issues, database details,
  operational measurements, absolute paths, evidence, transcripts, or internal
  runbooks appear in the candidate tree or candidate history.
- [ ] Review every third-party influence and artifact for public provenance,
  attribution, license compatibility, and redistribution permission.
- [ ] Confirm AIFactory implementation code and fixtures are original
  Apache-2.0 work; cited ideas remain clearly separated from source
  implementation.

## Repository controls and honest release notes

- [ ] Verify the hosting provider has an effective protected `main` ruleset with
  required CI checks, review requirements, and no unreviewed direct pushes.
  A manifest flag or `factory doctor` message is not proof of server-side
  enforcement.
- [ ] Review the release note's architecture, security, compatibility, and
  operating limitations against the implementation.
- [ ] Confirm Contract v1 and `verdict_v1` appear only as deprecated v0.x
  compatibility guidance; new-user guidance selects Contract v2 and
  `findings_v2`.
- [ ] Confirm all example repositories, identities, digests, and data are
  obviously synthetic.
- [ ] Confirm the autonomous builder is described as experimental and that no
  scientific or production-readiness claim exceeds the evidence.

## Separate shared-state approvals

Stop after the local candidate and evidence are ready. Obtain and record a new,
explicit operator approval immediately before each action:

- [ ] Approval to push the exact candidate branch.
- [ ] Approval to create or update the public pull request.
- [ ] Approval to merge the reviewed pull request.
- [ ] Approval to create and push the exact `0.2.0` tag.
- [ ] Approval to create the GitHub release from that tag.
- [ ] Approval to publish the exact built artifact to the package registry.

Re-run the relevant identity, verification, public-boundary, and protection gates
if the candidate changes between approvals. Never treat approval to push as
approval to tag, release, or publish.
