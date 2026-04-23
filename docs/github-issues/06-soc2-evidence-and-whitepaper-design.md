> **🚫 DEFERRED to Year 2.** Strategy pivoted 2026-04-22: Lucen is now primary product. SecGate becomes enterprise tier (Compliance Bridge $799/mo + SOC 2 evidence workflow $2k+/mo) only after Lucen reaches 1,000+ paying users. See `docs/roadmap.md` Phase 7 and `docs/business-analysis.md`. Issue contents preserved below for future reference.

---

## Goal

Explore how SecGate could support SOC 2 documentation and whitepaper generation without overclaiming current capability.

## Why

SOC 2 whitepapers are a possible future product direction, but the repo does not yet have the data model or workflow to support them credibly.

## Prerequisite

Issue 05 (compliance workflow spec) must be completed first. Control mappings and evidence model defined there are inputs to this document.

## This Issue Is a Design Doc — Not Code

Output: `docs/soc2-evidence-design.md`

Haiku should write the design memo. No source code changes.

## Document to Create: `docs/soc2-evidence-design.md`

Write this document with the following sections:

### 1. What "SOC 2 whitepaper support" means in practice

Be concrete. A whitepaper is not a marketing doc — it is a technical document describing controls, implementation, and evidence. Define:
- What artifact does SecGate produce?
- Who reads it? (auditors, customers, internal teams)
- What does it need to contain to be credible?

### 2. Scan findings vs compliance evidence — the distinction

Findings from scanners are NOT compliance evidence by themselves. A finding becomes evidence when:
- It is timestamped and attributed (who ran, when, what git hash)
- It is reviewed and approved by an authorized person
- It is linked to a specific control

Document this distinction clearly. Do not conflate scan output with audit-ready evidence.

### 3. Control mapping approach

Map SecGate's three finding types to SOC 2 Trust Service Criteria:

| Finding type | Tool | Candidate controls | Confidence |
|---|---|---|---|
| secret | gitleaks | CC6.1 (access control), CC6.7 (credential mgmt) | High |
| dependency | npm audit | CC7.1 (vulnerability mgmt) | High |
| code | semgrep | CC8.1 (change management) | Medium |

Extend, correct, or add confidence notes.

### 4. Missing capabilities for credible whitepaper generation

List what does NOT exist yet:
- Persistent storage (findings evaporate after each run)
- Identity (no concept of who ran the scan)
- Review workflow (no approval mechanism)
- Narrative generation (no prose, just JSON)
- Control mapping (no authoritative mapping file)
- Historical trending (no baseline comparison)

Be honest. This list is the product gap.

### 5. Required product capabilities before any implementation

Before writing whitepaper generation code, these must exist:
1. Stable finding schema (Issue 02)
2. Evidence artifact format (timestamped, signed or attributed)
3. Control mapping file (`src/controls.json` or similar)
4. Review/approval mechanism (CLI flag, file, or app)
5. Narrative template system

List in order of dependency.

### 6. What can vs cannot be automated

| Step | Automatable? | Why |
|------|-------------|-----|
| Running scans | Yes | CLI already does this |
| Timestamping evidence | Yes | Trivial |
| Mapping findings to controls | Partial | Rule-based, but needs human review |
| Writing narrative prose | Partial | LLM can draft, human must approve |
| Auditor approval | No | Legal requirement for human sign-off |
| Continuous monitoring narrative | Partial | Template + real data |

## Acceptance Criteria

- `docs/soc2-evidence-design.md` exists with all 6 sections completed
- Distinction between scan findings and audit evidence is clearly stated
- "Cannot be automated" list is honest and specific
- No implementation code written

## Scope

Write the document only. No new features, no LLM integration, no database schema.
