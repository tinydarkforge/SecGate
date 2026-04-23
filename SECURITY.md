# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SecGate, please report it privately.

**Do not open a public GitHub issue for security reports.**

Preferred channel:
- Open a [private security advisory](https://github.com/tinydarkforge/SecGate/security/advisories/new) on GitHub.

Include:
- A description of the vulnerability and its impact
- Steps to reproduce
- Affected version(s)
- Any suggested remediation

We will acknowledge receipt within 72 hours and aim to provide an initial assessment within 7 days.

## Supported Versions

Only the latest `main` branch receives security fixes at this stage.

## Scope

SecGate is a security scanning engine itself. Please report:
- Bypasses of the scanning/remediation logic
- Unsafe handling of scan artifacts, secrets, or intermediate files
- Supply-chain concerns in declared dependencies
- Any path traversal, command injection, or privilege escalation paths

Out of scope:
- Findings in third-party scanners invoked by SecGate (report upstream)
- Misconfiguration in end-user CI environments
