# Security policy

## Scope

This project drives AI agents with repository write access, handles provider
credentials through environment variables, and scans repositories for secrets.
Security issues in these areas are taken seriously.

## Security and authority model

The factory never holds the authority to release. Its loop code has no merge or
deploy capability (the source adapter exposes `open_pr`, never `merge`), and
`core.governance.assert_within_ceiling` refuses any action that targets a
configured production ref.

Agents run as separate processes with their own shells, so the real ceiling
must be enforced outside this package:

- protect `main` with a hosting-provider ruleset that requires CI and human
  approval and rejects direct pushes;
- give agents credentials that cannot merge, administer, or deploy;
- run agents in their native sandbox with least-privilege provider scopes;
- deny release verbs in the agent's permission settings. The reference Claude
  runner adds a deny list on every turn, which is pattern matching, not a
  sandbox.

The secret and public-content scanners are backstops. They may miss a novel
credential shape, private fact, or licensing problem, so every release also
requires a clean history-range scan and human review of the exact diff and
tracked-file manifest. See [PUBLIC_CONTENT_POLICY.md](docs/PUBLIC_CONTENT_POLICY.md)
and [RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md).

Agent transcripts and telemetry collected for analytics may contain source
code and secrets the agent read. They are redacted before storage, kept in
private encrypted storage, and never committed to this repository.

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
- Transcript redaction bypasses that let a secret reach analytics storage
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
