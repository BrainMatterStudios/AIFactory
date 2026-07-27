# Security policy

## Scope

This project drives AI agents with repository write access, handles provider
credentials through environment variables, and scans repositories for secrets.
Security issues in these areas are taken seriously.

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
