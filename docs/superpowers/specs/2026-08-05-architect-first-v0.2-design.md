# Architect-First Factory v0.2.0 Design

**Status:** Approved design, awaiting implementation-plan approval
**Date:** 2026-08-05
**Canonical repository:** `BrainMatterStudios/AIFactory`
**Target release:** `0.2.0`

## 1. Objective

Version 0.2.0 adds a real architecture-before-code boundary to the software
factory. For non-trivial work, the factory must produce a structured statement of
intent, validate that statement with deterministic policy, resolve or escalate
blocking ambiguity, and freeze the passing artifact before an implementation
agent can write code.

The release also changes model reviewers from authorities that emit verdicts into
sensors that emit typed findings. A deterministic router, operating over frozen
reports and an exact artifact hash, owns the final disposition.

The design is influenced by Stanislav Rumega's *Tell Your Coding Agent to Work as
an Architect First*. The implementation is original Apache-2.0 code. The project
will not copy the paper's CC-BY example artifacts, withheld schemas, or checker
implementation into the Apache-licensed package.

## 2. Release scope

Version 0.2.0 includes:

- canonical public/private repository ownership;
- an enforced public-content boundary;
- backward-compatible Contract v1 reading and deprecation;
- Contract v2 generation and validation;
- deterministic intent-gate findings and proof obligations;
- a contract-only pre-build phase;
- immutable artifact digests and implementation checkpoints;
- provider-neutral, hash-bound operator approval commands;
- append-only decision and evidence events outside the worktree;
- a findings-based reviewer protocol and deterministic disposition router;
- migration, operating, security, changelog, and release documentation;
- package version `0.2.0`.

The following are explicitly deferred to v0.3.0:

- a general design-level intermediate representation;
- a separate deterministic design gate;
- universal analyzer adapters for third-party SAST output;
- generic code-to-intent or code-to-design re-extraction;
- automated heuristic discovery or admission.

## 3. Repository ownership and public boundary

### 3.1 Canonical ownership

`AIFactory` is the only authoritative source for:

- the `software_factory` Python package;
- Contract schemas and deterministic policies;
- generic tests and synthetic fixtures;
- public adoption, migration, operating, and security documentation;
- package versions, changelog entries, and public release notes.

Generic code is developed directly in `AIFactory`. There is no private-to-public
copy or export command.

The private `software-factory` repository owns case-study evidence, internal
runbooks, private experiments, and private publication sources. It records a
pinned `AIFACTORY_REVISION`, states that the public repository is authoritative,
and documents a one-way public-to-private consumption policy. Its existing
duplicate package tree is transitional and must not be treated as an authoring
source.

### 3.2 Public content policy

The public repository may contain generic source code, synthetic examples,
public citations, and deliberately approved provenance statements. It must not
contain:

- `.ai/`, `.factory/`, transcripts, local evidence, screenshots, or generated
  private reports;
- secrets, credential values, DSNs with credentials, private keys, or tokens;
- private hostnames, account identifiers, internal repository URLs, or private
  absolute filesystem paths;
- customer data, private issue exports, private database schemas, production
  queries, or unpublished operational metrics;
- internal runbooks or incident artifacts;
- symlinks whose resolved targets leave the repository;
- unexpected binary artifacts;
- CC-BY material represented as Apache-2.0 implementation without attribution
  and an explicit licensing boundary.

A tracked-file public-boundary checker runs in CI. It uses explicit forbidden
path classes, secret-shape checks, private-location patterns, symlink resolution,
and a small binary allowlist. The checker reports exact paths and reasons and
fails closed when a file cannot be inspected.

The policy is a backstop, not a claim that a denylist can discover every private
fact. Release review still includes a human inspection of the exact diff and
tracked-file manifest.

## 4. Contract v2

### 4.1 Compatibility

Contract v1 remains readable and valid during the v0.x line. Reading v1 emits a
Python `DeprecationWarning`; CLI commands also print an explicit migration
warning. New generation always emits v2. Removing v1 support requires a future
major release.

The existing `validate_contract(doc, ...) -> list[str]` signature remains
source-compatible. A richer report API exposes validation errors, warnings,
intent findings, and proof obligations without changing the legacy return type.

### 4.2 Top-level shape

Contract v2 remains JSON and retains the existing fields:

- `issue`;
- `repo`;
- `schema_version`;
- `generated_at`;
- `tier`;
- `criteria`;
- `negotiation_rounds`;
- `data_fix_collapse`;
- optional `deferred_criteria`.

It adds a required `intent` object. `approved_git_rev` is superseded by the
controller-owned checkpoint and digest record; a repository-authored approval
field cannot prove its own approval.

### 4.3 Intent shape

The required intent fields are:

```json
{
  "summary": "Bounded description of the requested change",
  "scope": ["What will change"],
  "non_goals": ["What will not change"],
  "risk": {
    "distributed_or_async": false,
    "persistent_state": false,
    "irreversible_effects": false,
    "security_sensitive": false,
    "stochastic_or_ai": false
  },
  "ambiguities": [],
  "invariants": [],
  "failure_modes": [],
  "irreversible_operations": [],
  "dependencies": []
}
```

Child records use stable, unique IDs.

An ambiguity contains:

- `id`;
- `question`;
- `severity`: `blocking`, `high`, `medium`, or `low`;
- `proposed_default`;
- `status`: `unresolved`, `resolved`, or `delegated`;
- `resolution`;
- `authority`.

An invariant contains:

- `id`;
- `claim`;
- `mechanism`;
- `enforcement_layer`: `resource`, `platform`, `application`, `external`, or
  `none`;
- `evidence_obligation`.

A failure mode contains:

- `id`;
- `condition`;
- `response`;
- `bounded`;
- `bound`.

An irreversible operation contains:

- `id`;
- `operation`;
- `validation_precondition`;
- `rollback_or_compensation`;
- `human_owned`.

A dependency contains:

- `id`;
- `name`;
- `version`;
- `purpose`;
- `safety_or_enforcement_path`.

Each acceptance criterion keeps `id`, `description`, and `test_expression` and
adds `covers`, a non-empty list of intent element IDs when the contract declares
invariants or irreversible operations.

Unknown fields are errors in v2. The schema is a contract, and silently ignoring
an agent-invented field would make a missing check look accepted.

## 5. Deterministic intent gate

The gate returns the factory's existing `CheckResult` shape. Each non-PASS result
also carries a proof obligation: the failed predicate, admissible resolutions,
and the evidence required to discharge it.

The v0.2.0 policy checks:

1. schema, type, enum, ID uniqueness, and reference integrity;
2. absence of unresolved blocking ambiguity;
3. a concrete mechanism and enforcement layer for every invariant;
4. an explicit response for every declared applicable failure mode;
5. explicit bounds for declared retry, waiting, recovery, and resource-creation
   behavior;
6. validation before irreversible operations, plus rollback, compensation, or
   explicit human ownership;
7. exact dependency versions and stated purposes;
8. acceptance-criterion coverage for every invariant and irreversible operation;
9. conditional checks selected from declared risk properties rather than system
   labels;
10. fail-closed handling for unknown rule inputs and unreadable evidence.

Policy rules are pure functions with a pinned policy version. Model output cannot
change the rule set, severity mapping, or disposition.

Gate-level outcomes are:

- `PASS`: intent is admissible for the next stage;
- `SPEC_PENDING`: blocking questions require resolution;
- `APPROVAL_PENDING`: a human-owned decision requires a hash-bound approval;
- `BLOCKED`: malformed input, unknown policy data, inadmissible evidence, or a
  contract-author boundary violation.

## 6. Pre-build lifecycle

The build lifecycle becomes:

```text
issue -> classify -> contract phase -> deterministic intent gate
      -> T2 plan, when applicable -> hash-bound operator approval
      -> implementation -> objective tests -> review sensors
      -> deterministic disposition -> reverify -> pull request
```

For T1 and T2 work:

1. Create the isolated worktree.
2. Dispatch the contract-author persona.
3. Permit one tracked path: `<contracts_dir>/<issue>.json`.
4. Compare the complete tracked/untracked push surface before and after the turn.
5. Block if the turn changed any other tracked path.
6. Validate the artifact and run the deterministic intent policy.
7. If admissible, commit the contract separately.
8. Canonicalize the JSON and record its SHA-256, the contract commit SHA, schema
   version, and policy version.
9. Treat that commit as the implementation checkpoint.
10. Recompute the contract digest after worker and reviewer phases; any mutation
    blocks the build.

A pre-existing valid v1 contract may become the checkpoint with a deprecation
warning. A missing contract is generated as v2.

When blocking questions remain, no implementation agent runs. The controller
posts the typed questions and proposed defaults to the issue and returns
`SPEC_PENDING`. A later run may revise the contract from updated requirements.

RESTART resets the factory-owned branch to the contract checkpoint, not the
original development base. This preserves accepted intent while discarding the
failed implementation.

T2 planning occurs only after Gate 1. The planner receives the exact passing
contract. A plan digest is bound to its parent contract digest, so changing the
contract invalidates plan approval.

## 7. Hash-bound approvals

Labels remain optional status indicators and carry no authority.

The provider-neutral operator commands are:

```text
factory approve contract <issue> <sha256>
factory approve plan <issue> <sha256>
```

Approval records live in the controller state directory, outside the
agent-writable checkout. Each record includes repository identity, issue,
artifact kind, artifact digest, parent digest where applicable, approver,
timestamp, and rationale.

The CLI derives the default approver from the local operator identity and accepts
optional `--approver` and `--reason` values. The default rationale is "operator
approved exact artifact". These records prove which artifact the local controller
accepted; they are not cryptographic identity signatures.

The contract gate itself does not require a human for ordinary T1 work. An
operator approval is required when policy identifies a human-owned irreversible
decision or a blocking ambiguity resolved by human authority. T2 plan approval
remains mandatory.

An unreadable, corrupted, mismatched, stale, or wrong-parent approval fails
closed. Approval verification compares exact digests; filenames, labels, and
prose claims are not evidence.

## 8. Evidence and decision events

The controller appends JSON Lines decision events outside the worktree. Events
record:

- event schema version;
- repository and issue identity;
- run and stage identity;
- timestamp;
- artifact and parent digests;
- source, schema, policy, sensor, and configuration versions;
- findings and proof obligations;
- approval authority and rationale;
- disposition and its deterministic rule;
- previous-event digest, forming a tamper-evident chain.

The controller writes events; runner prompts never receive the state path. Secret
redaction occurs before persistence.

This is authority separation only when the runner is actually sandboxed from the
controller's state and credentials. The documentation must state that a separate
directory on an unrestricted shared host is organization, not an OS security
boundary.

## 9. Review sensors and deterministic disposition

### 9.1 Protocol

The v2 reviewer writes `.factory/review-findings.json`. The report contains:

- `schema_version`;
- sensor name and configured model/revision identifier;
- typed findings.

The controller compares the report's sensor identity with the sensor it actually
dispatched and records the configured identity as authoritative metadata. A
model-authored claim that it is a different or newer sensor is rejected.

Each finding contains:

- stable `id`;
- `category`: `security`, `correctness`, `architecture`, `requirements`, `test`,
  or `maintainability`;
- `severity`: `critical`, `high`, `medium`, `low`, or `info`;
- `confidence`: `high`, `medium`, or `low`;
- evidence locations with repository-relative file and optional line;
- message;
- required change.

The report cannot contain `PASS`, `REVISE`, `BLOCK`, `security_block`,
`wrong_design`, or any disposition hint. A model observes; policy decides.

Before each sensor dispatch, the controller hashes the exact reviewed diff. It
clears stale report files, runs the sensor, reads and validates the report, and
confirms the worktree artifact hash did not change. It immediately freezes the
validated report into controller-owned evidence with the artifact hash and
sensor/configuration versions.

### 9.2 Disposition policy

The pure router applies the following v0.2.0 policy over all required sensor
reports:

- any critical finding -> `BLOCK`;
- any high-severity security finding from the required security sensor ->
  `BLOCK`;
- high-severity architecture finding -> bounded `RESTART`, otherwise `BLOCK`;
- high-severity correctness, requirements, or test finding -> `REVISE`;
- medium, low, and info findings -> recorded warnings;
- no blocking findings, all required sensors available, unchanged artifact, and
  objective gates green -> `PASS`;
- malformed or unavailable required general sensor -> `REVISE`, then `BLOCK` at
  the existing revise cap;
- malformed or unavailable required security sensor -> `BLOCK`;
- disagreement -> the most conservative applicable disposition.

Worker feedback is rendered from typed findings. The model does not author the
final verdict string.

Existing installations may set `review_protocol: verdict_v1`. That path emits a
deprecation warning and remains supported during v0.x. A manifest with no
`review_protocol` field is interpreted as `verdict_v1` for compatibility. New
scaffolds write `findings_v2` explicitly, and the AIFactory repository exercises
v2 by default.

Overrides are decision events with authority and rationale. Their frequency and
outcome provide the false-positive evidence needed to tune policy later.

## 10. Error handling

The new control surfaces fail closed:

- unreadable contract -> `BLOCKED`;
- contract-author extra path -> `BLOCKED` and preserve the workspace;
- invalid or unknown v2 field -> `BLOCKED`;
- unresolved blocking ambiguity -> `SPEC_PENDING`;
- missing required approval -> `APPROVAL_PENDING`;
- stale or mismatched approval -> `BLOCKED`;
- contract mutation after checkpoint -> `BLOCKED` and preserve the workspace;
- missing or malformed security sensor report -> `BLOCKED`;
- missing or malformed general sensor report -> bounded `REVISE`, then `BLOCKED`;
- evidence-store corruption -> `BLOCKED`;
- decision-event append failure -> `BLOCKED` before push;
- public-boundary inspection failure -> CI failure and release stop.

No error path may be converted into PASS because a file, report, field, hash, or
sensor result is absent.

## 11. Verification strategy

Implementation follows test-driven development. Required coverage includes:

- v1 compatibility and deprecation behavior;
- v2 schema validation, unknown fields, enums, unique IDs, and references;
- every intent rule in pass, warning, pending, blocking, malformed, and
  not-applicable cases;
- contract-only path enforcement;
- canonical JSON digest stability;
- contract mutation detection after worker and sensor turns;
- checkpoint-preserving RESTART in a real Git repository;
- approval creation, exact matching, stale hash, wrong parent, corruption, and
  missing authority;
- decision-chain append, replay, redaction, and corruption detection;
- findings-report parsing and every disposition rule;
- missing, malformed, stale, contradictory, and artifact-mutating sensor reports;
- multi-sensor conservative routing;
- public-boundary violations for every forbidden content class;
- regression coverage for the existing judge, secret, budget, worktree, and
  interaction attacks;
- full test suite and pinned Ruff;
- tier policy and offline loop;
- installation and core import with no third-party dependencies.

The local CI wrapper's stale-environment defect is included: if its cached virtual
environment has Python but lacks pip or the pinned tool, the script recreates the
environment rather than reporting a misleading code failure.

## 12. Public release documentation

The release changes:

- package version to `0.2.0`;
- `CHANGELOG.md` with a `0.2.0` entry;
- `docs/releases/0.2.0.md` with capabilities, reasoning, threat model, migration,
  limitations, and Architect First attribution;
- `README.md`, `docs/ADOPTING.md`, `docs/OPERATING.md`, `KNOWN_ISSUES.md`, example
  configuration, and CLI help;
- the public-content policy and CI job;
- a release-readiness checklist requiring a protected `main` ruleset before
  publication.

The release notes must distinguish:

- deterministic observation from deterministic disposition;
- schema conformance from semantic truth;
- directory separation from OS-level authority separation;
- engineering implementation from scientific validation.

The project will not claim that structured intent reliably improves software.
The autonomous builder remains experimental.

## 13. Rollout and publication gate

New scaffolds generate Contract v2 and `findings_v2`. Existing Contract v1 and
`verdict_v1` users receive migration warnings and remain functional.

Implementation, tests, documentation, and local commits occur on feature
branches. The following shared-state actions require separate operator approval
after the complete diff and verification evidence are presented:

- pushing either feature branch;
- creating or merging pull requests;
- configuring GitHub rulesets;
- tagging `0.2.0`;
- creating a GitHub release;
- publishing to a package registry;
- updating any production system.
