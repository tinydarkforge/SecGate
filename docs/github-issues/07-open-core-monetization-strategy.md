> **🚫 SUPERSEDED 2026-04-22.** Replaced by `docs/business-analysis.md` (full pricing + tier strategy for Lucen primary, SecGate enterprise tier deferred to Year 2). Original SecGate-only monetization analysis preserved below for reference.

---

## Goal

Define a realistic monetization plan that preserves OSS adoption and trust.

## Why

Current codebase is better suited to open-core than a closed standalone product. That boundary needs to be explicit before building anything paid.

## Prerequisite

Issues 04, 05, 06 must be completed first. README positioning, workflow spec, and evidence design are inputs to this document.

## This Issue Is a Design Doc — Not Code

Output: `docs/monetization-memo.md`

Haiku should write the memo. No source code changes.

## Document to Create: `docs/monetization-memo.md`

Write this document with the following sections:

### 1. OSS core definition (what stays free forever)

Be explicit. The following must remain free or adoption dies:
- `secgate .` CLI scan
- JSON report output
- All three scanners (gitleaks, semgrep, npm audit)
- Report schema

State this as a commitment, not a maybe.

### 2. Paid feature candidates

Evaluate each against this test: "Does it require hosted workflow value a CLI cannot deliver?"

| Feature | Paid? | Requires app? | Why |
|---------|-------|--------------|-----|
| Evidence artifact export (PDF/HTML) | Maybe | No | CLI can do this |
| Control mapping to SOC 2 criteria | Maybe | No | CLI can do this |
| Team review + approval workflow | Yes | Yes | Multi-user, persistent state |
| Audit trail storage | Yes | Yes | Persistent, attributable |
| Historical trending / baseline | Yes | Yes | Persistent storage |
| LLM-drafted narrative whitepaper | Yes | Maybe | Compute cost |
| Custom rule configuration | No | No | OSS contribution |

Correct or extend this table based on issues 05 and 06 findings.

### 3. Pricing surface options

Evaluate these models:

| Model | Fits? | Why |
|-------|-------|-----|
| Per-seat SaaS | Maybe | Works if team review is the core value |
| Per-scan API | No | Commoditizes the core, builds nothing |
| Annual compliance workflow license | Maybe | Fits SOC 2 audit cycles |
| One-time whitepaper export fee | Weak | Not recurring |
| OSS + hosted (Grafana model) | Strong | Trust from OSS, revenue from hosted |

Pick one primary model and justify it.

### 4. What must stay public for trust and distribution

Security tools live or die on community trust. Keep public:
- Full scanner source code
- Report schema and format
- CLI behavior and flags
- All bug fixes

Never restrict: the ability to run a scan locally without phoning home.

### 5. First monetization path (practical, next 90 days)

Describe the smallest thing that can generate revenue without breaking OSS trust:
- What is the product? (one sentence)
- Who pays? (ICP: company size, role, compliance need)
- What is the price? (specific number or range)
- What does delivery look like? (hosted, CLI addon, export)
- What must be built first? (ordered list, max 5 items)

Be specific. "Enterprise tier" is not an answer.

## Acceptance Criteria

- `docs/monetization-memo.md` exists with all 5 sections completed
- OSS core is explicitly defined and committed to
- One pricing model is chosen with reasoning
- First monetization path has a specific ICP, price, and build list

## Scope

Write the document only. No pricing page, no billing code, no Stripe integration.
