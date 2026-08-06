# Security Policy

AegisRecon takes security seriously — for both the software we build and the
way we run it.

## Supported versions

| Version | Supported |
| --- | --- |
| latest (main) | ✅ |
| < 1.0 (alpha) | ⚠️ best effort |
| < 0.1 | ❌ |

## Reporting a vulnerability

Please do **not** open a public issue for a security vulnerability. Report it
privately so it can be fixed before disclosure.

Preferred channel: **security@aegisrecon.dev** (or open a GitHub Security
Advisory via *Report a vulnerability* on the repository).

Include in your report:

- Affected version and module.
- A minimal reproducer.
- Impact assessment (what an attacker could do).
- Any suggested fix, if you have one.

You should receive an acknowledgment within **48 hours**, and a timeline for a
fix within **7 days**.

## Disclosure policy

We follow a coordinated-disclosure model. Once a fix is shipped we publish an
advisory with a 30-day window before public disclosure to give users time to
upgrade.

## Security design notes

- **Scope enforcement is deny-by-default.** Assets outside an authorized
  program scope are never stored or probed.
- **Secrets are never logged.** A redacting handler scrubs keys, tokens and
  passwords from log output.
- **Output separation.** Machine-readable output on stdout; UI/logs on stderr.
- **No exploitation tooling.** AegisRecon cannot execute attacks; it only
  collects and organizes authorized information.

## Responsible researcher expectations

- Only test AegisRecon against assets you own or are explicitly authorized to test.
- Do not perform any action that could constitute an attack on a third party.