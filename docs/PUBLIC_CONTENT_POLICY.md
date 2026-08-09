# Public content policy

This repository is a public, generic software package. Publication safety is a
release property: every tracked file and every commit proposed for publication
must be suitable for an Apache-2.0 public repository.

The machine-readable rules live in
[`public-content-policy.json`](../public-content-policy.json). The scanner is a
fail-closed backstop; this document defines the human review boundary.

## Allowed content

- Generic implementation code, tests, and obviously synthetic fixtures.
- Public documentation and citations linked to their public sources.
- License and provenance statements reviewed for the material they cover.
- Narrowly allowlisted binary artifacts with explicit provenance and license.

## Prohibited content

- Secrets, tokens, private keys, credential-bearing connection strings, or
  credential values in source, fixtures, logs, or history.
- Private hosts, accounts, repositories, issue exports, database details,
  operational measurements, internal URLs, or absolute local paths.
- Customer data, internal runbooks, incident artifacts, screenshots,
  transcripts, generated reports, or local evidence/state directories.
- Symlinks that resolve outside the repository, unreadable tracked files, and
  unexpected binaries.
- Third-party material presented as original Apache-2.0 implementation, or
  material whose provenance and redistribution terms have not been reviewed.

Use synthetic names and values in public examples. A plausible-looking invented
credential or internal location creates needless ambiguity; make its synthetic
nature obvious.

## Required automated inspection

Run the current-tree scan throughout development:

```bash
uv run --extra dev python scripts/check-public-boundary.py
```

Before any branch is pushed for public review, scan the entire candidate history
after the reviewed public base:

```bash
uv run --extra dev python scripts/check-public-boundary.py \
  --base-ref "$REVIEWED_PUBLIC_BASE"
```

The current scan covers HEAD, the index, and the worktree's tracked surface. The
range scan also inspects every commit after the base through HEAD, including
content later deleted. An inspection error is a finding, not a skip.

A clean current-tree result is insufficient when an intermediate commit is
unsafe. Do not push that feature history. Create a sanitized publication history
from reviewed content, then run both scans against the publication candidate.
Never rely on deleting the file in a later commit.

## Required human inspection

The release reviewer must inspect the exact candidate range, not a summary made
from memory:

```bash
git diff --check "$REVIEWED_PUBLIC_BASE..HEAD"
git diff --stat "$REVIEWED_PUBLIC_BASE..HEAD"
git diff --name-status "$REVIEWED_PUBLIC_BASE..HEAD"
git diff "$REVIEWED_PUBLIC_BASE..HEAD"
git ls-files
```

Review every changed file and tracked path for private facts, generated evidence,
copied third-party expression, secrets, unsafe links, and unexpected binary
content. Confirm every citation is public and every non-original artifact has a
compatible license and clear provenance.

## Response to a finding

Stop publication. Preserve the scanner's rule and path without copying the
sensitive value into tickets or logs. Remove the material from the candidate
tree and all candidate commits, rotate any real credential through its provider,
and repeat current-tree, history-range, and exact-diff review. A scanner
allowlist change requires the same human provenance and license review as the
content it permits.

The policy cannot discover every private fact or licensing problem. Passing it
does not replace the [release checklist](RELEASE_CHECKLIST.md) or operator
judgment.
