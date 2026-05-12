> **⚠️ REVISED 2026-04-22.** SecGate is no longer the primary product. README should now position SecGate as: (1) standalone OSS scanner (current state) and (2) future enterprise tier for Lucen platform (year 2). Add prominent link to Lucen as the active product focus. See `docs/business-analysis.md` and `docs/roadmap.md`.

---

## Goal

Align project messaging with current product reality and define OSS vs paid boundary.

## Why

Current README overstates maturity ("AI SOC Engine", "autonomous"). Weakens trust. Trust is a monetization prerequisite for security tooling.

## Current Problems in README

Remove or tone down:
- "AI SOC Engine" — overstates capability
- "autonomous" mode claims — it runs `npm audit fix`, that's it
- Any implication of a full SOC 2 platform today
- Version numbers in the product name ("SecGate v7")

## Target README Structure

Rewrite `README.md` with this exact section order:

```
# SecGate

One-paragraph description: what it does TODAY (scan orchestration + remediation guidance for CI)

## Install

npm install -g secgate

## Usage

secgate .              # scan current directory, dry-run
secgate . --apply      # execute fixable remediations
secgate . --debug      # verbose output

## What it scans

- Secrets (gitleaks)
- Code patterns (semgrep)
- Dependency vulnerabilities (npm audit)

## Output

JSON report at secgate-v7-report.json. Schema: [link to docs/report-schema.md or inline]

## Prerequisites

[link to docs/prerequisites.md]

## CI Usage

[link to docs/ci-example.yml or inline snippet]

## Roadmap (not yet built)

- Compliance workflow: evidence collection, review, audit trail
- Control mapping: findings → SOC 2 controls
- Hosted: dashboard, team review, exports

## OSS vs Paid

Core scanner (this repo): free, open source, MIT
Future hosted features: paid (workflow, evidence, team review)

## License

MIT
```

## File to Create: `docs/report-schema.md`

Document the stable JSON shape from `secgate-v7-report.json`:

```json
{
  "version": "7.0",
  "timestamp": "ISO8601",
  "target": "string",
  "mode": "dry-run | apply",
  "status": "PASS | FAIL",
  "summary": { "critical": 0, "high": 0, "medium": 0, "low": 0 },
  "findings": [
    {
      "tool": "gitleaks | semgrep | npm",
      "type": "secret | code | dependency",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "signature": "string",
      "message": "string",
      "fixable": true
    }
  ],
  "intelligence": {
    "riskScore": 0,
    "attackSurface": ["string"],
    "reasoning": [],
    "recommendations": ["string"]
  },
  "remediation": {
    "plan": [],
    "stagedChanges": [],
    "executed": [],
    "blocked": [],
    "confidence": 100
  }
}
```

## Verify

- No mention of "SOC platform", "AI SOC", "autonomous" in README
- README install/usage commands match actual CLI behavior
- Roadmap section clearly labeled "not yet built"

## Acceptance Criteria

- README accurately describes today's capabilities
- Future features framed as roadmap, not current
- OSS/paid boundary documented
- `docs/report-schema.md` exists

## Scope

Edit `README.md` and create `docs/report-schema.md` only. Do NOT modify source code.
