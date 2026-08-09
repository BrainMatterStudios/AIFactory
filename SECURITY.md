# Security policy

## Scope

This project drives AI agents with repository write access, handles provider
credentials through environment variables, and scans repositories for secrets.
Security issues in these areas are taken seriously.

## Security and authority model

Version 0.2 separates three writable surfaces:

- the agent worktree, which is untrusted runner output;
- controller state, which holds exact approvals and digest-chained decision
  events outside all repository worktrees; and
- the public candidate, which must pass current-tree and history-range content
  inspection before publication.

Contract v2 is frozen and hashed before implementation. Contract and T2 plan
approvals bind exact SHA-256 digests; a plan also binds the exact parent contract
digest. Under `findings_v2`, model reviewers emit typed observations against an
exact artifact fingerprint, while deterministic code owns the disposition.
Missing, unreadable, stale, malformed, mismatched, or corrupt authority evidence
fails closed.

These controls narrow authority; they are not containment. A state directory on
an unrestricted shared host is not an OS security boundary. Run agents in a
sandbox that cannot read controller state or release credentials, grant
least-privilege provider scopes, and enforce protected `main` at the hosting
provider. The reference runner's command filters are pattern matching, not a
sandbox. Approval identity is a controller attestation, not a cryptographic
signature, and digest-chained events are tamper-evident rather than an external
transparency log.

The secret and public-content scanners are backstops. They may miss a novel
credential shape, private fact, or licensing problem, so every release also
requires a clean history-range scan and human review of the exact diff and
tracked-file manifest. See [PUBLIC_CONTENT_POLICY.md](docs/PUBLIC_CONTENT_POLICY.md)
and [RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md).

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately by emailing **security@brainmatterstudios.com** with:

- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- Which version or commit is affected

You will receive an acknowledgement within 72 hours. If you do not hear back,
follow up via a GitHub issue with `[SECURITY]` in the title — omit details
there and wait for a private channel to be established.

## What to report

- Secret or credential exposure through error paths, logs, or output
- Prompt injection that causes the agent to cross the prod boundary
- Bypass of the governance ceiling (`assert_within_ceiling`) or kill switch
- Bypass of exact contract/plan approval, contract immutability, findings-only
  review authority, or decision-chain verification
- Public-boundary scanner bypasses involving current content, intermediate Git
  history, links, binaries, or provenance
- Shell injection through config values or adapter inputs
- Arbitrary code execution through the manifest or plugin loader

## What is out of scope

- Issues in third-party dependencies (report upstream; we'll update the dep)
- Theoretical attacks with no practical path on a correctly configured install
- Operator misconfiguration (e.g. storing credentials in the manifest file)

## Disclosure

We aim to publish a fix within 30 days of a confirmed report. We will
coordinate the disclosure timeline with you and credit you in the release
notes unless you prefer to remain anonymous.
