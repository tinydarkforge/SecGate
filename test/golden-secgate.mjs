#!/usr/bin/env node
// Golden snapshot test — locks the aggregation contract against a hand-crafted
// scanner output set.
//
// The expected values below are the locked contract. Any code change that
// alters them is intentional and must update both the change and the lock
// in the same PR (with rationale in the description).
//
// Why inline expectations instead of a JSON snapshot file:
//   - The diff in code review surfaces *exactly* what changed (severity,
//     count, score) instead of an opaque snapshot blob.
//   - Updating requires the author to acknowledge the change explicitly,
//     not just regenerate a file.

import path from "path";
import { fileURLToPath } from "url";

const libDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "lib");

const { makeFindingProcessor } = await import(`${libDir}/scanners.mjs`);
const { computeScore, computeToolScores, SCORE_VERSION } = await import(`${libDir}/score.mjs`);
const { summarize, resolveStatus, TOOLS } = await import(`${libDir}/report.mjs`);
const { CONFIG_DEFAULTS } = await import(`${libDir}/config.mjs`);

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

function assertEq(a, b, msg) {
  if (a !== b) throw new Error(`${msg ?? "eq"}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}

console.log("\nSecGate golden snapshot tests");
console.log("-----------------------------");

// Hand-crafted raw findings — covers every aggregation feature:
//   - 2 CRITICAL, 3 HIGH, 2 MEDIUM, 2 LOW, 1 UNKNOWN  (before transforms)
//   - 1 duplicate (collapses)
//   - 1 severity override (npm-audit.outdated-pkg → LOW)
//   - 1 ignore-glob match (drops trivy-license-MIT)
//   - 5 tools represented
const RAW_FINDINGS = [
  { tool: "semgrep",  type: "code",       severity: "HIGH",     signature: "javascript.lang.security.audit.dangerous-spawn-shell.dangerous-spawn-shell",                                                      message: "spawn shell",      file: "src/exec.js",  line: 42 },
  { tool: "semgrep",  type: "code",       severity: "HIGH",     signature: "javascript.lang.security.audit.dangerous-spawn-shell.dangerous-spawn-shell",                                                      message: "spawn shell",      file: "src/exec.js",  line: 42 }, // duplicate → drops
  { tool: "semgrep",  type: "code",       severity: "MEDIUM",   signature: "javascript.lang.security.audit.path-traversal",                                                                                   message: "path-traversal",   file: "src/api.js",   line: 18 },
  { tool: "gitleaks", type: "secret",     severity: "CRITICAL", signature: "aws-access-token",                                                                                                                message: "AKIA...",           file: ".env",          line: 3  },
  { tool: "gitleaks", type: "secret",     severity: "CRITICAL", signature: "stripe-live-key",                                                                                                                 message: "sk_live_...",        file: "config/secrets.js", line: 7  },
  { tool: "npm",      type: "dependency", severity: "HIGH",     signature: "npm-audit.lodash",                                                                                                                 message: "prototype pollution", file: "package.json", line: null },
  { tool: "npm",      type: "dependency", severity: "HIGH",     signature: "npm-audit.outdated-pkg",                                                                                                          message: "old release",        file: "package.json", line: null }, // overridden → LOW
  { tool: "osv",      type: "dependency", severity: "MEDIUM",   signature: "GHSA-abcd-1234-efgh",                                                                                                              message: "advisory",          file: "package-lock.json", line: 220 },
  { tool: "osv",      type: "dependency", severity: "LOW",      signature: "GHSA-wxyz-5678-stuv",                                                                                                              message: "advisory",          file: "package-lock.json", line: 540 },
  { tool: "trivy",    type: "iac",        severity: "UNKNOWN",  signature: "AVD-AWS-0028",                                                                                                                     message: "S3 public",          file: "infra/s3.tf",   line: 8  },
  { tool: "trivy",    type: "license",    severity: "LOW",      signature: "trivy-license-MIT",                                                                                                                message: "MIT",                file: null,             line: null }  // ignored
];

const target = "/tmp/secgate-golden-fixture";

function buildConfig() {
  return {
    ...CONFIG_DEFAULTS,
    severityOverrides: [
      { rule: "npm-audit.outdated-pkg", severity: "LOW" }
    ],
    ignore: ["trivy-license-*"],
    excludePaths: []
  };
}

function aggregate() {
  const findings = [];
  const suppressions = { count: 0, byRule: {} };
  const addFinding = makeFindingProcessor(buildConfig(), target, findings, suppressions);
  for (const f of RAW_FINDINGS) addFinding(f);
  return { findings, suppressions };
}

/* ── locked contract: total counts ── */

test("golden: total finding count after dedup + ignore + override", () => {
  const { findings } = aggregate();
  // 11 raw → minus 1 duplicate → minus 1 ignored → 9 findings
  assertEq(findings.length, 9, "9 findings after transforms");
});

test("golden: per-tool counts", () => {
  const { findings } = aggregate();
  const byTool = {};
  for (const f of findings) byTool[f.tool] = (byTool[f.tool] || 0) + 1;
  assertEq(byTool.semgrep,  2, "semgrep: 2");
  assertEq(byTool.gitleaks, 2, "gitleaks: 2");
  assertEq(byTool.npm,      2, "npm: 2");
  assertEq(byTool.osv,      2, "osv: 2");
  assertEq(byTool.trivy,    1, "trivy: 1 (license ignored)");
});

/* ── locked contract: severity distribution ── */

test("golden: severity summary", () => {
  const { findings } = aggregate();
  const s = summarize(findings);
  //   CRITICAL: 2 (aws-access-token, stripe-live-key)
  //   HIGH:     2 (dangerous-spawn-shell, npm-audit.lodash)
  //   MEDIUM:   2 (path-traversal, GHSA-abcd)
  //   LOW:      2 (GHSA-wxyz, npm-audit.outdated-pkg [overridden])
  //   UNKNOWN:  1 (AVD-AWS-0028)
  assertEq(s.critical, 2, "critical");
  assertEq(s.high,     2, "high");
  assertEq(s.medium,   2, "medium");
  assertEq(s.low,      2, "low");
  assertEq(s.unknown,  1, "unknown");
});

/* ── locked contract: score ── */

test("golden: Security Score", () => {
  const { findings } = aggregate();
  // 100 - (2*25) - (2*10) - (2*3) - (2*1) - (1*0) = 100 - 50 - 20 - 6 - 2 = 22
  assertEq(computeScore(findings), 22, "score = 22");
});

test("golden: per-tool scores", () => {
  const { findings } = aggregate();
  const ts = computeToolScores(findings, TOOLS);
  // semgrep:    100 - 10 - 3       = 87
  // gitleaks:   100 - 25 - 25      = 50
  // npm:        100 - 10 - 1       = 89
  // osv:        100 - 3 - 1        = 96
  // trivy:      100 - 0 (UNKNOWN)  = 100
  // trivyImage: 100 (no findings)
  assertEq(ts.semgrep,    87,  "semgrep score");
  assertEq(ts.gitleaks,   50,  "gitleaks score");
  assertEq(ts.npm,        89,  "npm score");
  assertEq(ts.osv,        96,  "osv score");
  assertEq(ts.trivy,      100, "trivy score (UNKNOWN no penalty)");
  assertEq(ts.trivyImage, 100, "trivyImage score (no findings)");
});

/* ── locked contract: gate status ── */

test("golden: resolveStatus = FAIL (critical + high present)", () => {
  const { findings } = aggregate();
  assertEq(resolveStatus(findings, ["critical", "high"], false), "FAIL", "FAIL on default failOn");
});

test("golden: resolveStatus = PASS when failOn = critical only and we strip critical", () => {
  // Strip the 2 CRITICAL findings, leave high+medium+low+unknown
  const reduced = aggregate().findings.filter(f => f.severity !== "CRITICAL");
  assertEq(resolveStatus(reduced, ["critical"], false), "PASS", "PASS when no critical");
});

/* ── locked contract: SCORE_VERSION ── */

test("golden: SCORE_VERSION is v1 (any bump invalidates dashboards)", () => {
  assertEq(SCORE_VERSION, "v1", "SCORE_VERSION pinned");
});

console.log("-----------------------------");
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
