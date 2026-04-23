# ADR-0005: No External API / Dashboard / Telemetry in v1

- **Status:** Accepted
- **Date:** 2026-04-23
- **Deciders:** TinyDarkForge

## Context

Every commercial scanner (Snyk, Aikido, GitGuardian, Sonar) eventually builds a cloud dashboard. The revenue model demands it: per-seat pricing, workflow triage, Jira sync, executive reporting. The product grows a control plane.

For SecGate v1 the question is: do we build that control plane now?

Against:
- **Operational cost** — a SaaS control plane means running a DB, a web app, an auth system, billing, on-call rotations. That's headcount and cash we don't have as a solo-founder operation.
- **Trust posture** — "no account, no telemetry" is a distinctive, defensible positioning. Once we phone home, we're just a cheaper Snyk.
- **Security surface** — a cloud endpoint that receives scan data is a juicy target. A compromise leaks customer vulnerability data. Not having the endpoint removes the surface.
- **Air-gap friendliness** — regulated customers (gov, finance, healthcare) cannot use SaaS tools. v1 working entirely offline opens that market.
- **Simpler mental model** — "SecGate is a CLI that writes files" is trivially understandable. No sign-up, no SDKs, no webhooks.

For:
- **Revenue model** — SaaS is the standard path. Without it we need another monetization angle.
- **Triage UX** — JSON + HTML reports are inferior to a real dashboard for large orgs.
- **Historical trends** — no "your CVE count over time" without a backend.

## Decision

**SecGate v1 will ship no external API, no cloud dashboard, and no telemetry. The CLI + local artifacts are the entire product.**

- No phone-home on install or run.
- No anonymous usage metrics.
- No SaaS dashboard.
- No auth system.
- No account required — ever, at any tier — for core scanning.

Monetization, if and when it appears, will come from:
- Premium scanner bundles (private Semgrep rule packs, expanded language coverage).
- Enterprise support contracts.
- Hosted versions run **by the customer** on their infra, not ours.
- NOT from selling insights gathered from customer scans.

## Consequences

### Positive

- Zero operational cost for the project. No servers, no on-call, no breach liability.
- Clear positioning: "the anti-Snyk." Privacy-first, self-hosted by default.
- Addressable market includes regulated / air-gapped customers excluded by SaaS tools.
- Reversibility — adding a dashboard later is easier than removing one.
- No incentive misalignment: we cannot be tempted to mine customer scan data.

### Negative

- Weaker UX for large orgs that expect a dashboard. Mitigated by JSON-first output — customers can BYO dashboard (Grafana, Superset, whatever).
- Harder to measure engagement and drive product decisions. We rely on GitHub issues and direct feedback instead of analytics.
- SaaS revenue model is off the table for v1.

### Neutral

- This ADR is explicitly scoped to **v1**. v2 may revisit; the decision will require a new ADR superseding this one.

## Alternatives Considered

### Opt-in telemetry ("help us improve SecGate")
Rejected for v1. Even opt-in telemetry creates an endpoint we must operate, secure, and keep honest. Not worth the cost/risk for product feedback we can get from GitHub.

### Optional cloud dashboard behind a paywall
Rejected for v1. Would require the entire control plane anyway. Revisit when we have headcount to operate it.

### Run-level webhook to customer's own endpoint
Possible future feature — lets customers route to their own systems (Slack, Jira) without us running anything. Low priority; not needed for v1.

## References

- [`docs/comparison.md`](../comparison.md) — "no telemetry by default" as unique positioning
- [ADR-0004 — self-contained HTML report](0004-self-contained-html-report.md) — same "artifacts as product" principle
- [`docs/threat-model.md`](../threat-model.md) — absence of external API removes a major threat surface
