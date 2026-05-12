#!/usr/bin/env node
// Unit tests for lib/confidence.mjs — curated profile demotion logic.

import { getConfidence, bucketByConfidence, informationalReason } from "../lib/confidence.mjs";

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ok  ${name}`);
    passed++;
  } catch (e) {
    console.log(`  FAIL ${name}`);
    console.log(`       ${e.message}`);
    failed++;
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || "assertion failed");
}

console.log("\nSecGate confidence tests");
console.log("------------------------");

// ── Curated profile ──────────────────────────────────────────────────
test("curated: HIGH semgrep finding stays actionable", () => {
  const f = { tool: "semgrep", severity: "HIGH", signature: "javascript.lang.security.audit.eval" };
  assert(getConfidence(f, "curated") === "actionable");
});

test("curated: HTML missing-integrity demoted to informational", () => {
  const f = { tool: "semgrep", severity: "MEDIUM", signature: "html.security.audit.missing-integrity.missing-integrity" };
  assert(getConfidence(f, "curated") === "informational");
});

test("curated: trivyImage LOW base-image CVE demoted", () => {
  const f = { tool: "trivyImage", severity: "LOW", signature: "trivy-image:node:20-slim:CVE-2026-12345" };
  assert(getConfidence(f, "curated") === "informational");
});

test("curated: trivyImage MEDIUM base-image CVE demoted", () => {
  const f = { tool: "trivyImage", severity: "MEDIUM", signature: "trivy-image:node:20-slim:CVE-2026-99999" };
  assert(getConfidence(f, "curated") === "informational");
});

test("curated: trivyImage HIGH base-image CVE stays actionable", () => {
  const f = { tool: "trivyImage", severity: "HIGH", signature: "trivy-image:node:20-slim:CVE-2026-77777" };
  assert(getConfidence(f, "curated") === "actionable");
});

test("curated: stale CVE (>5yr old) demoted", () => {
  const f = { tool: "osv", severity: "MEDIUM", signature: "lodash:CVE-2011-3374" };
  assert(getConfidence(f, "curated") === "informational");
});

test("curated: stale CRITICAL CVE stays actionable", () => {
  const f = { tool: "osv", severity: "CRITICAL", signature: "lodash:CVE-2011-3374" };
  assert(getConfidence(f, "curated") === "actionable");
});

test("curated: recent CVE stays actionable", () => {
  const currentYear = new Date().getFullYear();
  const f = { tool: "osv", severity: "MEDIUM", signature: `lodash:CVE-${currentYear}-12345` };
  assert(getConfidence(f, "curated") === "actionable");
});

test("curated: UNKNOWN severity demoted", () => {
  const f = { tool: "semgrep", severity: "UNKNOWN", signature: "some.rule" };
  assert(getConfidence(f, "curated") === "informational");
});

test("curated: gitleaks high secret stays actionable", () => {
  const f = { tool: "gitleaks", severity: "HIGH", signature: "aws-access-token" };
  assert(getConfidence(f, "curated") === "actionable");
});

test("curated: trivy license finding demoted (type=license)", () => {
  const f = { tool: "trivy", type: "license", severity: "LOW", signature: "MIT:lodash", message: "License MIT flagged" };
  assert(getConfidence(f, "curated") === "informational");
});

test("curated: trivy image LOW with tool=trivy + scanMode=image demoted", () => {
  const f = { tool: "trivy", type: "dependency", severity: "LOW", scanMode: "image", signature: "trivy-image:node:20-slim:CVE-2026-99999", image: "node:20-slim" };
  assert(getConfidence(f, "curated") === "informational");
});

test("curated: trivy image MEDIUM via signature prefix demoted", () => {
  const f = { tool: "trivy", type: "dependency", severity: "MEDIUM", signature: "trivy-image:python:3.12-slim:CVE-2026-1234" };
  assert(getConfidence(f, "curated") === "informational");
});

test("curated: trivy image HIGH stays actionable even with scanMode=image", () => {
  const f = { tool: "trivy", type: "dependency", severity: "HIGH", scanMode: "image", signature: "trivy-image:node:20-slim:CVE-2026-77777" };
  assert(getConfidence(f, "curated") === "actionable");
});

test("curated: trivy filesystem dependency CVE stays actionable (not image)", () => {
  const f = { tool: "trivy", type: "dependency", severity: "MEDIUM", signature: "trivy-vuln:lodash:CVE-2026-1234", file: "package-lock.json" };
  assert(getConfidence(f, "curated") === "actionable");
});

test("strict: license finding stays actionable", () => {
  const f = { tool: "trivy", type: "license", severity: "LOW", signature: "MIT:lodash" };
  assert(getConfidence(f, "strict") === "actionable");
});

// ── Strict profile ───────────────────────────────────────────────────
test("strict: HTML missing-integrity stays actionable", () => {
  const f = { tool: "semgrep", severity: "MEDIUM", signature: "html.security.audit.missing-integrity.missing-integrity" };
  assert(getConfidence(f, "strict") === "actionable");
});

test("strict: trivyImage LOW stays actionable", () => {
  const f = { tool: "trivyImage", severity: "LOW", signature: "trivy-image:node:20-slim:CVE-2011-3374" };
  assert(getConfidence(f, "strict") === "actionable");
});

test("strict: UNKNOWN severity stays actionable", () => {
  const f = { tool: "semgrep", severity: "UNKNOWN", signature: "some.rule" };
  assert(getConfidence(f, "strict") === "actionable");
});

// ── Bucket helper ────────────────────────────────────────────────────
test("bucketByConfidence splits correctly under curated", () => {
  const findings = [
    { tool: "semgrep", severity: "HIGH", signature: "a.real.rule" },
    { tool: "semgrep", severity: "MEDIUM", signature: "html.security.audit.missing-integrity.x" },
    { tool: "trivyImage", severity: "LOW", signature: "trivy-image:base:CVE-2026-1" },
    { tool: "gitleaks", severity: "CRITICAL", signature: "aws-key" }
  ];
  const { actionable, informational } = bucketByConfidence(findings, "curated");
  assert(actionable.length === 2, `expected 2 actionable, got ${actionable.length}`);
  assert(informational.length === 2, `expected 2 informational, got ${informational.length}`);
});

test("bucketByConfidence puts everything in actionable under strict", () => {
  const findings = [
    { tool: "semgrep", severity: "MEDIUM", signature: "html.security.audit.missing-integrity.x" },
    { tool: "trivyImage", severity: "LOW", signature: "trivy-image:base:CVE-2011-3374" },
    { tool: "semgrep", severity: "UNKNOWN", signature: "x" }
  ];
  const { actionable, informational } = bucketByConfidence(findings, "strict");
  assert(actionable.length === 3);
  assert(informational.length === 0);
});

// ── Reason labels ────────────────────────────────────────────────────
test("informationalReason: stale CVE returns N-yr-old label", () => {
  const f = { tool: "osv", severity: "MEDIUM", signature: "lodash:CVE-2011-3374" };
  const r = informationalReason(f);
  assert(/yr-old CVE/.test(r), `expected 'yr-old CVE', got '${r}'`);
});

test("informationalReason: trivyImage LOW returns base-image label", () => {
  const f = { tool: "trivyImage", severity: "LOW", signature: "trivy-image:base:CVE-2026-1" };
  assert(informationalReason(f) === "base-image OS package");
});

test("informationalReason: noisy rule pattern returns 'noisy rule'", () => {
  const f = { tool: "semgrep", severity: "MEDIUM", signature: "html.security.audit.missing-integrity.x" };
  assert(informationalReason(f) === "noisy rule");
});

test("informationalReason: UNKNOWN returns 'unknown severity'", () => {
  const f = { tool: "semgrep", severity: "UNKNOWN", signature: "x" };
  assert(informationalReason(f) === "unknown severity");
});

// ── Display-filtering invariants (curated/strict never drop a finding) ──
const SAMPLE_FINDINGS = [
  { tool: "semgrep", severity: "HIGH", signature: "javascript.lang.security.audit.eval" },
  { tool: "semgrep", severity: "MEDIUM", signature: "html.security.audit.missing-integrity.x" },
  { tool: "trivy", severity: "LOW", scanMode: "image", signature: "trivy-image:node:20-slim:CVE-2026-1" },
  { tool: "trivy", severity: "MEDIUM", type: "license", signature: "MIT" },
  { tool: "osv", severity: "UNKNOWN", signature: "GHSA-xxxx" },
  { tool: "trivy", severity: "MEDIUM", signature: "trivy-image:node:20-slim:CVE-2010-1234" },
  { tool: "npm", severity: "CRITICAL", signature: "GHSA-yyyy" },
  { tool: "gitleaks", severity: "HIGH", signature: "aws-access-key" },
];

test("curated: bucketing partitions findings (nothing dropped)", () => {
  const { actionable, informational } = bucketByConfidence(SAMPLE_FINDINGS, "curated");
  assert(actionable.length + informational.length === SAMPLE_FINDINGS.length,
    `expected ${SAMPLE_FINDINGS.length}, got ${actionable.length}+${informational.length}`);
  const all = new Set([...actionable, ...informational]);
  for (const f of SAMPLE_FINDINGS) assert(all.has(f), "finding missing from buckets");
  assert(informational.length > 0, "curated should demote some of the noisy samples");
});

test("strict: every finding is actionable (no demotion, nothing dropped)", () => {
  const { actionable, informational } = bucketByConfidence(SAMPLE_FINDINGS, "strict");
  assert(informational.length === 0, "strict should not demote anything");
  assert(actionable.length === SAMPLE_FINDINGS.length, "strict should keep every finding actionable");
});

test("curated and strict see the same total finding count", () => {
  const c = bucketByConfidence(SAMPLE_FINDINGS, "curated");
  const s = bucketByConfidence(SAMPLE_FINDINGS, "strict");
  assert(c.actionable.length + c.informational.length === s.actionable.length + s.informational.length,
    "profile must not change the underlying finding count — only the actionable/informational split");
});

console.log("------------------------");
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
