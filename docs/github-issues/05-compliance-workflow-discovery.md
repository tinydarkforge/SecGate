> **🚫 DEFERRED to Year 2.** Strategy pivoted 2026-04-22: Lucen is now primary product (vibe coder market, $79–$999 one-shot reports + SaaS). SecGate becomes enterprise tier (SOC 2 evidence workflow) only after Lucen reaches 1,000+ paying users. See `docs/roadmap.md` Phase 7 and `docs/business-analysis.md`. Issue contents preserved below for future reference.

---

## Goal

Decide whether SecGate should become a small app by validating a real compliance workflow.

## Why

An app only makes sense if it solves workflow problems a CLI cannot. Do not build UI first.

## This Issue Is a Design Doc — Not Code

Output: `docs/compliance-workflow-spec.md`

Haiku should write the spec document. No source code changes.

## Document to Create: `docs/compliance-workflow-spec.md`

Write this document with the following sections (answer each honestly):

### 1. Minimum compliance workflow worth building

Define the smallest end-to-end workflow that delivers value. Example starting point to evaluate:
- Engineer runs `secgate .` → findings collected
- Findings mapped to SOC 2 controls (e.g., CC6.1, CC7.2)
- Evidence artifact generated (timestamped JSON + metadata)
- Reviewer approves/rejects evidence in some UI or workflow
- Audit trail stored (who approved, when, for which control)

Answer: Is this the right workflow? What's missing? What's simpler?

### 2. Actors, inputs, approvals, outputs

| Actor | Input | Action | Output |
|-------|-------|--------|--------|
| Engineer | codebase | runs scan | findings JSON |
| Security lead | findings | reviews + maps | evidence artifact |
| Auditor | evidence | reviews | approval/rejection |

Extend or correct this table.

### 3. Where scanner evidence fits

Which scan outputs map to which SOC 2 control categories:
- Secret findings → CC6 (Logical and Physical Access Controls)
- Dependency vulns → CC7 (System Operations)
- Code patterns → CC8 (Change Management)

Verify or correct these mappings.

### 4. System requirements for audit trails

List what the system must store for each evidence artifact:
- Who ran the scan
- When
- What version of secgate
- What was scanned (git hash / path)
- What findings existed
- Who reviewed
- Approval status

What else is required?

### 5. App vs CLI recommendation

Answer: Does the workflow require an app (persistent state, multi-user, UI) or can it work as a CLI + file output?

Decision criteria:
- If single-user, no reviewer, no persistent state needed → CLI is enough
- If multi-user, reviewer approval, audit trail needed → app required

State recommendation clearly with reasoning.

## Acceptance Criteria

- `docs/compliance-workflow-spec.md` exists and answers all 5 sections
- App vs CLI recommendation is explicit and backed by the workflow analysis
- Document does not claim to be a product spec — it is a discovery document

## Scope

Write the document only. No UI, no database, no new features.
