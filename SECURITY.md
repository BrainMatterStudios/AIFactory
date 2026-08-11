# Security policy

## Scope

This project drives AI agents with repository write access, handles provider
credentials through environment variables, and scans repositories for secrets.
Security issues in these areas are taken seriously.

## Security and authority model

Version 0.3 separates three writable surfaces:

- the agent worktree, which is untrusted runner output;
- controller state, which holds exact approvals and digest-chained decision
  events outside all repository worktrees; and
- the public candidate, which must pass current-tree and history-range content
  inspection before publication.

Contract v2 is frozen and hashed before implementation. Contract, Design, and
compatibility-plan approvals bind exact SHA-256 digests; a Design or plan also
binds the exact parent Contract digest. Under `findings_v2`, model reviewers emit typed observations against an
exact artifact fingerprint, while deterministic code owns the disposition.
Missing, unreadable, stale, malformed, mismatched, or corrupt authority evidence
fails closed.

For an adopted T2 Design workflow, the exact Contract selects a sticky protocol,
then Design IR v1 binds that parent, the configuration, required capabilities,
repository fingerprint, and bounded analyzer evidence. A deterministic gate can
pass only those exact inputs. Human approval then binds the exact Design digest
and parent Contract digest; any identity-bearing Design change requires new
approval, while changed evidence requires a fresh gate.

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

## Analyzer and inspection boundaries

Installed analyzers are trusted code, like installed plugins. Normalized
analyzer evidence does not sandbox installed analyzer code. The fork broker
suppresses output and applies descriptor, byte, frame, time, encoding, schema,
and cleanup bounds; the controller fingerprints the repository before and after
execution. This detects persistent workspace mutation but cannot prove there was
no transient workspace mutation or external side effect. The broker supports
the release's macOS/Linux environments; a runtime without `fork`, including
native Windows, fails unavailable.

Ordinary current macOS APFS volumes cannot prove no-atime reads. The required
harness analyzer fails closed with high-security evidence for every present
supported harness file rather than content-opening it. Use a verifiable no-atime
volume or environment. Restoring metadata is another mutation and is not a safe
workaround; disabling a required analyzer does not preserve Design authority.

The four Design inspection commands, `factory status`, and `factory doctor` do
not write or repair lifecycle authority. Status is a linearizable "as observed"
projection, not a filesystem snapshot or repository lock. Logical read-only
claims exclude access time because portable no-atime reads are not universally
available, and inspection does not restore timestamps.

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
- Bypass of exact Contract/Plan/Design approval, artifact immutability,
  capability non-elevation, deterministic Design gating, findings-only review
  authority, or decision-chain verification
- Analyzer output, descriptor, process, path, size, timeout, redaction, or
  workspace-fingerprint boundary bypasses
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
