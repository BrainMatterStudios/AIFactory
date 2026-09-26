# Controller-Bound Contract Revision Design

**Date:** 2026-09-16

**Status:** approved

**Programme:** AIFactory 0.3 operational validation

## 1. Purpose

Stage 1 operational validation exposed a gap between model-authored Contract v2
intent and controller-owned execution policy. The validation-cell controller
had already fixed the exact base revision, four writable product paths,
model-only network profile, local-bundle publication ceiling, and six
verification commands. Contract authoring did not receive those facts. It saw
only the issue text and Contract v2 schema, then produced a schema-valid
contract that widened the change surface, introduced `git fetch origin/main`,
and deferred a requirement that the controller already knew was exact.

The exact approval gate prevented implementation, so no authority escaped. The
remaining product defect is operational: an operator can approve a pending
contract, but cannot reject that exact artifact with bounded feedback and ask
for a replacement. A fresh cell and another stochastic authoring turn is not a
sound revision protocol.

This design adds two linked authorities:

1. a controller-owned execution-constraint envelope that is visible to the
   contract author and cryptographically bound to contract approval; and
2. an exact-digest contract revision request that permits one replacement
   authoring turn without granting implementation authority.

The change is general AIFactory infrastructure. It is not a target-project
prompt special case.

## 2. Goals

- Bind every newly authored contract to the exact controller execution ceiling
  that applies to its build.
- Prevent a model-authored contract from changing base, writable paths,
  network profile, publication mode, or verification commands.
- Make those constraints visible in the contract-author brief without exposing
  credentials, absolute controller paths, or adapter implementation options.
- Let an operator reject one exact pending contract with bounded, inert
  feedback and obtain one newly authored candidate with a new digest.
- Retain the rejected contract, constraint envelope, feedback, and lineage for
  audit and replay.
- Preserve exact approval: a contract approval must bind both the contract
  digest and its constraint digest.
- Fail closed on missing, malformed, stale, conflicting, or changed authority.
- Keep released Contract v2 documents readable and avoid reinterpreting an old
  approval under the new policy.

## 3. Non-goals

- Contract v3 or a general rewrite of the Contract v2 intent schema.
- Treating model-authored prose as machine execution authority.
- Automatically deciding whether free-text scope is semantically correct.
- Automatically revising a contract without an exact operator request.
- Editing an accepted contract or revoking published approval history.
- Adding remote issue labels, comments, pull requests, pushes, merges, or
  deployments.
- Migrating or approving any retained field-trial contract.
- Reusing a stopped or retired validation cell.

## 4. Trust model

Contract intent and execution authority remain separate.

- The model authors Contract v2 intent. Its prose and criteria are untrusted
  declarative data reviewed by deterministic policy and a human operator.
- The controller authors the execution-constraint document from already parsed,
  typed configuration and exact build inputs.
- The model cannot write, replace, or supplement that document.
- The approval store binds the contract digest as the artifact and the
  constraint digest as its parent.
- The workspace, Leash executor, verifier, and publication controller continue
  to enforce the actual ceiling. The new envelope records and binds that ceiling;
  it does not replace runtime enforcement.
- A contradiction in Contract v2 prose cannot widen operational authority. It
  is a human-review defect resolved through exact-digest revision.

This distinction is deliberate. Attempting to infer authoritative paths,
network operations, or publication rights from unrestricted natural language
would create another parser-shaped security boundary.

## 5. Canonical execution-constraint document

The controller constructs one `contract-execution-constraints-v1` document per
contract lifecycle:

```json
{
  "schema_version": "contract-execution-constraints-v1",
  "repository": "example/integration-target",
  "issue": "900001",
  "tier": "T2",
  "base_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "publication_mode": "local_bundle",
  "network_profile": "model-only-v1",
  "implementation_writable_paths": [
    "src/feature.py",
    "tests/test_feature.py"
  ],
  "verification_commands": [
    {
      "name": "targeted",
      "argv": ["python", "-m", "pytest", "-q", "tests/test_feature.py"],
      "expected_exit": "zero",
      "environment_profile": "default"
    }
  ]
}
```

The example abbreviates the verification-command list; a real document contains
every configured command in configured order.

The document is built only from:

- normalized repository and issue identities;
- the classified tier;
- the exact commit observed from the prepared workspace's authenticated base
  surface (a branch name or other symbolic ref is never stored as the base);
- `PublicationMode`;
- `ExecutionPolicySpec.implementation_writable_paths`;
- `ExecutionPolicySpec.network_profile`; and
- every `VerificationCommandSpec` field.

It never contains adapter options, absolute paths, state roots, image references,
environment values, credentials, authorization URLs, or model-auth storage.
Constrained authoring rejects a verification command whose argument is flagged
by the existing credential scanner; secrets belong in separately controlled
runtime environment profiles, never command arguments or configuration.
Canonical JSON bytes determine `constraint_digest` using SHA-256. Construction
rejects an absent or non-exact base, non-canonical repository identity, invalid
issue, unsupported tier or publication mode, and any invalid execution policy.

The order of writable paths and commands is approval-bearing because the
controller already treats configured order as part of policy. No sorting or
set projection silently changes that order.

## 6. Contract envelope v3

Contract v2 remains the model-authored document format. The controller-side
`ContractEnvelope` advances from schema 2 to schema 3 and adds:

```text
constraint_document: dict[str, JSON]
constraint_digest: 64-character lowercase SHA-256
previous_contract_digest: 64-character lowercase SHA-256 or null
revision_request_digest: 64-character lowercase SHA-256 or null
```

For an initial candidate, both lineage fields are null. For a revised candidate,
both are required and identify the rejected contract and the exact request that
authorized replacement.

Envelope validation recomputes both artifact digests, validates the complete
constraint schema, and requires repository and issue identity equality across
the envelope, Contract v2 document, and constraint document. The base,
publication mode, and execution policy are re-derived by orchestration and must
produce the same constraint document before a pending envelope may resume.

The pending contract file continues to contain the exact Contract v2 bytes the
model wrote. The constraint document is separate controller data in the
envelope; the controller never edits model-authored Contract v2 prose after the
turn.

## 7. Contract-author boundary

The initial contract-author brief receives a canonical, pretty-printed view of
the constraint document and its digest. The brief states that:

- the constraints are controller-owned facts, not suggestions;
- free-text scope and acceptance criteria must fit inside them;
- the author must not invent broader paths, commands, network access,
  publication, or a different base; and
- inability to express a necessary requirement inside the ceiling is recorded
  as a blocking ambiguity rather than a widened contract.

The author still writes exactly one Contract v2 file and receives no controller
path. The constraint document is prompt data only; it is persisted by the
controller from its typed source, never parsed back from model output.

The existing strict Contract v2 validator and deterministic intent policy still
run. Constraints do not make a semantically poor contract acceptable. Exact
human review remains mandatory whenever intent policy requires approval.

## 8. Exact-digest approval

New constrained contracts use policy version `intent-v2`. A contract approval
record must contain:

```text
artifact_kind = contract
artifact_digest = current contract digest
parent_digest = current constraint digest
```

The generated command becomes:

```bash
factory --config <manifest> approve contract <issue> <contract-digest> \
  --parent <constraint-digest>
```

The `approve contract` parser accepts `--parent` and requires it for an
`intent-v2` pending contract. The command authenticates the current pending
envelope before writing approval. A supplied contract digest or parent digest
that is stale, absent, malformed, or not current is rejected without writing
authority.

Existing `intent-v1` approvals retain their historical `parent_digest = null`
meaning. They are never treated as approvals for `intent-v2` envelopes.

## 9. Revision request

### 9.1 Operator document

Revision feedback is supplied as an owner-private JSON file:

```json
{
  "schema_version": "contract-revision-feedback-v1",
  "required_changes": [
    "Use only the four controller-listed implementation paths.",
    "Remove every acceptance step that fetches or contacts a source remote.",
    "Treat exactly three relocated probes as a current requirement, not deferred work."
  ]
}
```

The schema has exactly two fields. `required_changes` contains one to 20
non-empty strings, each at most 1,000 Unicode scalar values; the canonical file
is at most 32 KiB. Duplicate strings, control characters other than normalized
newlines, non-finite JSON, duplicate object keys, and unknown fields are
rejected. Feedback is treated as untrusted quoted data in the next model brief
and receives no decision, approval, or execution authority.

### 9.2 CLI

The operator records a revision request with:

```bash
factory --config <manifest> revise contract <issue> <contract-digest> \
  --parent <constraint-digest> \
  --feedback-file <owner-private-json>
```

The command:

1. resolves the configured repository and controller root;
2. descriptor-authenticates the exact current pending Contract Envelope v3;
3. requires both supplied digests to match it;
4. refuses accepted, absent, legacy, or already-requested authority;
5. reads and validates the feedback through a pinned regular-file descriptor;
6. creates one immutable revision-request record with mode `0600`; and
7. prints only fixed identifiers and digests, never feedback text.

Recording a revision request does not approve, accept, delete, or replace a
contract. It authorizes one bounded replacement authoring turn.

### 9.3 Request authority

The canonical `contract-revision-request-v1` record contains:

```text
repository
issue
rejected_contract_digest
constraint_digest
feedback_document
feedback_digest
requested_by
requested_at
request_digest
```

`request_digest` covers every preceding field. `requested_by` follows approval
identity resolution: explicit CLI value first, then repository Git operator
identity. The timestamp is controller-generated UTC.

## 10. Revision lifecycle

On the next build, orchestration loads the current pending envelope and any
revision request through authenticated stores.

- No request: materialize the exact pending Contract v2 artifact and stop at the
  existing approval gate without another model turn.
- Exact current request: run one contract-author revision turn.
- Missing, malformed, stale, conflicting, or mismatched request: block before a
  model turn.

The revision brief includes:

- the issue;
- the rejected Contract v2 document;
- the unchanged canonical constraint document and digest; and
- the quoted `required_changes` list.

The revised author has the same one-file write boundary as the initial author.
It must replace the Contract v2 file, not edit source or tests. After strict
validation, the controller requires a new contract digest and re-derives the
same constraint digest. Reproducing the rejected digest is a blocked revision,
not success.

Successful publication is an atomic compare-and-swap transition:

1. reauthenticate the current pending envelope and request;
2. write and fsync immutable generation records for the rejected envelope and
   consumed request;
3. write and fsync the new pending Envelope v3 with lineage fields;
4. atomically replace only the current-pending pointer;
5. re-open and reauthenticate the new current envelope; and
6. mark the request consumed only as part of that successful transition.

Any failure leaves the old pending envelope and unconsumed request current.
There is no half-revised state and no automatic retry. A second revision needs
a new exact operator request against the new pending digest.

## 11. Storage and replay

Revision state lives under the existing controller contract authority root,
outside product worktrees:

```text
.factory/contracts/
  issue-<id>.json                     current pending envelope
  accepted-issue-<id>.json            accepted envelope
  generations/
    issue-<id>.<contract-digest>.json retained rejected envelope
  revisions/
    issue-<id>.<request-digest>.json  immutable request generation
```

All directories and files use the contract store's descriptor-pinned,
no-follow, owner-private patterns. Symlinks, hard links, FIFOs, device files,
unexpected names, permission drift, duplicate current records, and transition
debris fail closed.

Decision events add `constraint_digest`, `previous_contract_digest`, and
`revision_request_digest` to the contract-stage evidence. Lifecycle replay
requires exact continuity from constraint document through contract approval,
Design IR parent, and final publication authority.

## 12. Compatibility

- Contract v1 and v2 document validation remains unchanged.
- Envelope schema 2 plus policy `intent-v1` remains readable for inspection and
  replay.
- New authoring writes Envelope schema 3 plus policy `intent-v2`.
- Schema-2 pending authority cannot resume as schema 3 and receives a fixed
  `legacy pending contract requires a fresh lifecycle` diagnostic.
- Schema-2 accepted authority remains valid only for the historical lifecycle
  that recorded it.
- No old approval is copied, upgraded, or inferred.
- Generic builds receive a constraint document from their exact typed defaults
  as well as explicit configuration; absence of an explicit execution-policy
  block does not mean absence of a ceiling.

## 13. Failure handling and diagnostics

Operator-facing diagnostics are fixed codes and never include exception,
feedback, contract, path, environment, or model output text. Required codes
include:

```text
contract-constraints-invalid
contract-constraints-stale
contract-approval-parent-mismatch
contract-revision-absent
contract-revision-stale
contract-revision-conflict
contract-revision-feedback-invalid
contract-revision-no-change
contract-revision-store-unavailable
```

Unexpected exceptions collapse to a fixed external-failure diagnostic. Secret
or prompt-like strings embedded in malformed typed errors, feedback, model
output, or paths must not reach the CLI reason.

Budget exhaustion, runner timeout, workspace drift, or author boundary failure
during revision keeps the old pending contract and request available for
inspection. It never falls through to approval, design, or implementation.

## 14. Security properties

- Constraint construction accepts typed policy objects, not arbitrary mapping
  data from the model.
- Constraint and revision digests use canonical JSON and exact identity fields.
- Approval is impossible without both current digests.
- Feedback can influence only one contract-author turn; it cannot select tools,
  roles, models, paths, publication, or execution policy.
- The revision author cannot read controller state or write outside the contract
  artifact.
- No raw contract, feedback, exception, OAuth data, absolute state path, or
  model response enters decision summaries or fixed failure messages.
- Retained history is append-only and a rejected artifact can never become
  current again through the revision operation.

## 15. Test strategy

Implementation follows test-driven development.

### Constraint unit tests

- Exact projection from `ExecutionPolicySpec`, publication mode, base,
  repository, issue, and tier.
- Stable canonical digest and approval-bearing configured order.
- Rejection of invalid identities, base, enum values, paths, and commands.
- Proof that adapter options, controller paths, environment values, and secrets
  cannot appear in the document.

### Contract store tests

- Envelope schema-3 round trip and exact constraint reauthentication.
- Legacy schema-2 inspection without schema-3 promotion.
- Constraint mutation, digest mismatch, stale policy, link attacks, permission
  drift, transition debris, and conflicting records.
- Atomic revision success and failure at every filesystem transition.
- Retention of rejected envelopes and consumed requests.

### Contract phase tests

- Initial author receives sanitized exact constraints.
- Pending resume requires the same constraint digest.
- Exact revision request yields one author turn and a new digest.
- Stale or mismatched request blocks before dispatch.
- No-change revision blocks and preserves old authority.
- Failed, timed-out, or out-of-bound author turn preserves old authority.
- Approval requires the constraint parent digest.
- Design and implementation cannot start from a rejected or unapproved
  candidate.

### CLI tests

- `approve contract --parent` authenticates the current Envelope v3.
- `revise contract` accepts one strict owner-private feedback file.
- Accepted, absent, legacy, duplicate, stale, and malformed requests fail
  without writes.
- CLI output remains fixed and non-echoing under adversarial feedback and typed
  error metadata.

### Integration and regression

- Existing Contract v1/v2 and approval tests continue to pass.
- Contract -> Design IR -> exact approval continuity includes the new constraint
  digest.
- Full repository test suite, lint, compilation, and diff checks pass.
- Independent review covers authority escalation, filesystem transitions,
  compatibility, and non-echoing diagnostics.

## 16. External validation sequence

Retained field-trial cells and contracts remain private evidence only and are
never reused or approved. Repository-specific identities, paths, feedback, and
evidence stay outside AIFactory Git.

After this feature is implemented, verified, independently reviewed, and committed locally:

1. build an exact wheel from the accepted local commit;
2. create a new disposable validation cell with a new instance identity;
3. authenticate in that cell and repeat import, dependency bootstrap, seal, and
   configure;
4. author a new constrained contract;
5. approve it only if both its intent and controller constraints are correct;
6. if intent is still semantically wrong, record an exact revision request and
   prove the replacement flow in that same active lifecycle;
7. continue to Design IR only after exact contract approval; and
8. stop and retain the cell after terminal evidence.

No AIFactory push, target-checkout mutation, remote source mutation, production
database access, merge, deployment, or publication is authorized by this design.

## 17. Acceptance

The feature is acceptable when:

- every newly authored contract is paired with a canonical controller-owned
  constraint document;
- exact contract approval is parent-bound to the current constraint digest;
- stale or widened machine authority cannot resume or pass approval;
- an operator can request one exact revision without approving or deleting the
  rejected artifact;
- successful revision creates a new digest with complete immutable lineage;
- failed revision preserves the former current authority and request;
- legacy authority is readable but never silently upgraded;
- diagnostics remain fixed and non-echoing;
- all focused and full verification passes; and
- a synthetic fresh-cell rehearsal reaches a correct contract approval
  boundary without touching a user checkout or shared state.
