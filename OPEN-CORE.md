```text
░▒▓█ SECGATE · OPEN-CORE BOUNDARY █▓▒░
```

# Open-Core Boundary

This document defines what stays MIT-licensed and free in SecGate forever, and what may become paid extensions in the future. It exists to be explicit **before** monetization happens, not after.

---

## OSS core — stays free, MIT-licensed, always

These capabilities are shipped today and will not move behind a paywall:

- **Scan orchestration** — wrapping and running Semgrep, Gitleaks, osv-scanner, Trivy, npm audit
- **Finding normalization** — unified severity model, deduplication, `addFinding()` pipeline
- **SARIF 2.1.0 output** — standard format, no lock-in
- **JSON report** — full schema, machine-readable, no proprietary fields
- **Self-contained HTML report** — per-scanner tabs, dark-mode, zero external assets
- **Baseline / ratcheting** — `--update-baseline`, `--baseline`, suppress known findings
- **Inline suppressions** — `secgate:ignore` comments, audit-logged
- **Config file** — `.secgate.config.json`, severity overrides, scanner toggles
- **CLI** — `secgate`, `npx @tinydarkforge/secgate`, GitHub composite Action
- **Local and air-gapped use** — no required network calls, no telemetry, no account

If you build on any of the above today, it will still be there and free in 18 months.

---

## Paid extensions — roadmap, not shipped

These do not exist. They are candidates for a future paid tier. None of them remove or gate features that are free today.

| Candidate | What it would add |
|-----------|-------------------|
| Hosted dashboard | Web UI for viewing findings across runs without managing files locally |
| Org-wide policy management | Centralized severity overrides and ignore lists applied across multiple repos |
| Multi-repo aggregation | Aggregate findings from many repos into one view, trend tracking over time |
| Compliance evidence packs | Mapped finding exports for SOC 2, ISO 27001, PCI-DSS control families |
| SSO / team access controls | SAML/OIDC login, role-based access to findings and reports |
| Audit log retention | Long-term storage and querying of scan history and suppression decisions |
| Jira / ServiceNow integration | Push findings as tickets, track remediation lifecycle |
| SLA support | Response time guarantees, dedicated contact |

Building any of these requires revenue to justify. They will not ship as OSS because they require hosted infrastructure that costs money to run. If they ship, they will be priced transparently with a public self-hosted option where feasible.

---

## What this means for contributors

- PRs that extend the OSS core (new scanner adapters, report improvements, baseline logic, CLI flags) are welcome and will stay MIT.
- PRs that build toward hosted infrastructure or multi-tenant features will be evaluated case by case. If a contribution materially enables a paid tier, that will be disclosed before merge.
- Contributors will not be asked to sign a CLA that would allow relicensing of the OSS core. The MIT license on the core is permanent.

---

## The test

Before adding any capability to the paid tier, the question is: does this remove something that currently exists for free? If yes, that is a rug-pull and will not happen. If it is a net-new capability that requires hosted infrastructure, it is a fair extension.

---

*Last updated: 2026-04-23*
