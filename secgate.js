#!/usr/bin/env node

import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import { loadConfig } from "./lib/config.mjs";
import { makeFindingProcessor } from "./lib/scanners.mjs";
import {
  runGitleaks,
  runSemgrep,
  runOsvScanner,
  runTrivy,
  runTrivyImage,
  runNpmAudit
} from "./lib/scanners.mjs";
import { loadBaseline, writeBaseline, applyBaseline } from "./lib/baseline.mjs";
import { analyze, remediate } from "./lib/intelligence.mjs";
import {
  TOOLS,
  summarize,
  resolveStatus,
  applyPathStripping,
  renderHtml,
  buildSarif
} from "./lib/report.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(
  fs.readFileSync(path.join(__dirname, "package.json"), "utf-8")
);

/* ────────────────────────────────────────────────────────────────────────────
   CLI FLAGS
   ──────────────────────────────────────────────────────────────────────────── */

const argv = process.argv.slice(2);

if (argv.includes("--version") || argv.includes("-v")) {
  console.log(pkg.version);
  process.exit(0);
}

if (argv.includes("--help") || argv.includes("-h")) {
  console.log(`
    ╔═══════╗   █████ █████ █████ █████ █████ █████ █████
    ║ ╔═══╗ ║   █     █     █     █     █   █   █   █
    ║ ║ ⊙ ║ ║   █████ ████  █     █ ███ █████   █   ████
    ║ ╚═══╝ ║       █ █     █     █   █ █   █   █   █
    ╠═══════╣   █████ █████ █████ █████ █   █   █   █████
╔═══╬═══════╬═══╗
║   ║ [===] ║   ║  v${pkg.version} — tiny security gate for CI/CD
╚═══╬═══════╬═══╝  Semgrep · Gitleaks · osv-scanner · Trivy · npm
    ╚═╝   ╚═╝

Usage:
  secgate [target] [options]

Arguments:
  target              Directory to scan (default: current directory)

Options:
  --apply             Execute fixable remediations (default: dry-run).
                      Requires SECGATE_CONFIRM_APPLY=1 or an interactive
                      y/n confirmation. Runs npm with --ignore-scripts.
  --output-dir <dir>  Directory to write report files (default: target)
  --strip-paths       Relativize target to repo basename in the report.
                      Auto-enabled when CI=true.
  --format <fmt>      Output formats: json,html (default) or sarif
  --baseline          Compare against baseline; fail only on net-new findings
  --update-baseline   Write current findings to baseline file then exit 0
  --debug             Print raw scanner output
  --version, -v       Print version and exit
  --help, -h          Show this help

Environment:
  SECGATE_CONFIRM_APPLY=1   Non-interactive confirmation for --apply
  CI=true                   Auto-enables --strip-paths

Config file (.secgate.config.json in target):
  failOn             Severities that trigger exit 1 (default: ["critical","high"])
  scanners           Map of scanner name → true/false to enable/disable
  severityOverrides  Array of {rule, severity} to override matched findings
  ignore             Array of signatures to drop entirely
  baselineFile       Path to baseline JSON (default: .secgate-baseline.json)
  customSemgrepRules Path to additional semgrep rules (passed as --config=<path>)

Precedence: CLI flag > config file > defaults

Exit codes:
  0  PASS — no findings matching failOn severities (or all matched baseline)
  1  FAIL — net-new findings matching failOn severities
  2  Invalid target or CLI error

Output:
  secgate-v7-report.json    machine-readable report
  <repo-name>.html          premium HTML report
  <repo-name>.sarif.json    SARIF 2.1.0 report (when --format sarif)
`);
  process.exit(0);
}

function argValue(flag) {
  const i = argv.indexOf(flag);
  if (i === -1) return null;
  const v = argv[i + 1];
  if (!v || v.startsWith("--")) return null;
  return v;
}

const rawTarget    = argv[0] && !argv[0].startsWith("--") ? argv[0] : ".";
const APPLY        = argv.includes("--apply");
const DEBUG        = argv.includes("--debug");
const STRIP_PATHS  = argv.includes("--strip-paths") || process.env.CI === "true";
const OUTPUT_DIR_FLAG = argValue("--output-dir");
const FORMAT_IDX   = argv.indexOf("--format");
const FORMAT       = FORMAT_IDX >= 0 ? (argv[FORMAT_IDX + 1] || "json,html") : "json,html";
const EMIT_SARIF   = FORMAT.split(",").map(s => s.trim()).includes("sarif");
const BASELINE_MODE    = argv.includes("--baseline");
const UPDATE_BASELINE  = argv.includes("--update-baseline");

const target = path.resolve(rawTarget);

if (!fs.existsSync(target)) {
  console.error(`Target not found: ${rawTarget}`);
  process.exit(2);
}
if (!fs.statSync(target).isDirectory()) {
  console.error(`Target is not a directory: ${rawTarget}`);
  process.exit(2);
}

const outputDir = OUTPUT_DIR_FLAG ? path.resolve(OUTPUT_DIR_FLAG) : target;

if (!OUTPUT_DIR_FLAG) {
  if (process.cwd() !== target) {
    console.error(
      `Warning: cwd (${process.cwd()}) differs from target (${target}); ` +
        `writing reports to target. Use --output-dir to override.`
    );
  }
} else {
  if (!fs.existsSync(outputDir)) {
    try {
      fs.mkdirSync(outputDir, { recursive: true });
    } catch (e) {
      console.error(`Cannot create --output-dir ${outputDir}: ${e.message}`);
      process.exit(2);
    }
  }
  if (!fs.statSync(outputDir).isDirectory()) {
    console.error(`--output-dir is not a directory: ${outputDir}`);
    process.exit(2);
  }
}

const repoName     = path.basename(path.resolve(target));
const reportTarget = STRIP_PATHS ? repoName : target;
const outputFile   = path.join(outputDir, "secgate-v7-report.json");

/* ────────────────────────────────────────────────────────────────────────────
   CONFIG + STATE
   ──────────────────────────────────────────────────────────────────────────── */

const config = loadConfig(target);

const findings    = [];
const suppressions = { count: 0, byRule: {} };

const toolStatus     = Object.fromEntries(TOOLS.map(t => [t, "pending"]));
const toolSkipReason = {};

const report = {
  version:   pkg.version,
  timestamp: new Date().toISOString(),
  target:    reportTarget,
  mode:      APPLY ? "apply" : "dry-run",
  status:    "PASS",
  summary:   { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
  findings:  [],
  tools:     toolStatus,
  toolSkipReason,
  suppressions,
  intelligence: { riskScore: 0, attackSurface: [], reasoning: [], recommendations: [] },
  remediation:  { plan: [], stagedChanges: [], executed: [], blocked: [], confidence: 100 },
  auditLog:  []
};

function auditLog(event, detail) {
  const entry = { timestamp: new Date().toISOString(), event, target: reportTarget, ...detail };
  report.auditLog.push(entry);
  console.error(`[audit] ${JSON.stringify(entry)}`);
}

function debugFn(label, data) {
  if (DEBUG) {
    console.log(`\n[DEBUG] ${label}`);
    console.log(String(data).slice(0, 1000));
  }
}

/* ────────────────────────────────────────────────────────────────────────────
   APPLY CONFIRMATION
   ──────────────────────────────────────────────────────────────────────────── */

function confirmApplyOrExit() {
  if (!APPLY) return;
  if (process.env.SECGATE_CONFIRM_APPLY === "1") {
    auditLog("apply_confirmed", { via: "env" });
    return;
  }
  if (process.stdin.isTTY) {
    process.stderr.write(
      `\nSecGate --apply will execute remediations against:\n  ${target}\n` +
        `npm invocations run with --ignore-scripts. Proceed? [y/N] `
    );
    let answer = "";
    try {
      const buf = Buffer.alloc(64);
      const n = fs.readSync(0, buf, 0, buf.length, null);
      answer = buf.slice(0, n).toString("utf-8").trim().toLowerCase();
    } catch {
      answer = "";
    }
    if (answer !== "y" && answer !== "yes") {
      console.error("Aborted: --apply not confirmed.");
      process.exit(2);
    }
    auditLog("apply_confirmed", { via: "tty" });
    return;
  }
  console.error(
    "Refusing to run --apply without confirmation. " +
      "Set SECGATE_CONFIRM_APPLY=1 or run in a TTY."
  );
  process.exit(2);
}

/* ────────────────────────────────────────────────────────────────────────────
   SCAN
   ──────────────────────────────────────────────────────────────────────────── */

console.log(`
░▒▓█ SECGATE v${pkg.version} █▓▒░`);
console.log("Target:", reportTarget);
console.log("Mode:  ", APPLY ? "APPLY" : "DRY RUN");
console.log("────────────────────────────────");

confirmApplyOrExit();
if (APPLY) {
  auditLog("apply_start", { outputDir });
}

const addFinding = makeFindingProcessor(config, target, findings, suppressions);

function applyResult(toolKey, result) {
  toolStatus[toolKey] = result.status;
  if (result.skipReason) toolSkipReason[toolKey] = result.skipReason;
}

applyResult("semgrep",    runSemgrep(target, config, addFinding, debugFn));
applyResult("gitleaks",   runGitleaks(target, config, addFinding, debugFn));
applyResult("npm",        runNpmAudit(target, config, addFinding, debugFn));
applyResult("osv",        runOsvScanner(target, config, addFinding, debugFn));
applyResult("trivy",      runTrivy(target, config, addFinding, debugFn));
applyResult("trivyImage", runTrivyImage(target, config, addFinding, debugFn));

/* ────────────────────────────────────────────────────────────────────────────
   BASELINE
   ──────────────────────────────────────────────────────────────────────────── */

if (UPDATE_BASELINE) {
  const baselinePath = writeBaseline(config, target, findings);
  console.log(`\nBaseline written: ${baselinePath} (${findings.length} findings)`);
  process.exit(0);
}

let baselineDiff   = null;
let activeFindings = findings;

if (BASELINE_MODE) {
  const baseline = loadBaseline(config, target);
  if (baseline) {
    const { annotated, baselineMatchedCount } = applyBaseline(findings, baseline);
    activeFindings = annotated;
    const netNew = annotated.filter(f => !f.baseline).length;
    baselineDiff = { netNew, baselineMatchedCount };
    console.log(`\nBaseline: ${baselineMatchedCount} matched, ${netNew} net-new`);
  } else {
    console.log("\nBaseline: no baseline file found, treating all findings as net-new");
  }
}

/* ────────────────────────────────────────────────────────────────────────────
   FINALIZE REPORT
   ──────────────────────────────────────────────────────────────────────────── */

report.findings      = activeFindings;
if (baselineDiff) report.baselineDiff = baselineDiff;
report.toolSkipReason = toolSkipReason;
report.summary       = summarize(activeFindings);
report.intelligence  = analyze(activeFindings);
report.remediation   = remediate(activeFindings, {
  apply:        APPLY,
  target,
  reportTarget,
  auditLog
});
report.status = resolveStatus(activeFindings, config.failOn, BASELINE_MODE);

/* ────────────────────────────────────────────────────────────────────────────
   OUTPUT
   ──────────────────────────────────────────────────────────────────────────── */

console.log("\n────────────────────────────────");
console.log("STATUS:", report.status);
console.log("RISK SCORE:", report.intelligence.riskScore);
console.log("CONFIDENCE:", report.remediation.confidence + "%");

console.log("\nSCANNER STATUS:");
for (const t of TOOLS) {
  const reason = toolSkipReason[t] ? ` (${toolSkipReason[t]})` : "";
  console.log(`- ${t.padEnd(10)} ${toolStatus[t]}${reason}`);
}

console.log("\nTOP ISSUES:");
activeFindings.slice(0, 5).forEach(f =>
  console.log("-", f.signature, "|", f.severity, f.baseline ? "[baseline]" : "")
);

console.log("\nRECOMMENDATIONS:");
report.intelligence.recommendations.forEach(r => console.log("-", r));

if (suppressions.count > 0) {
  console.log(`\nSUPPRESSED: ${suppressions.count} finding(s) via inline comment`);
}

if (APPLY) {
  console.log("\nEXECUTED FIXES:");
  report.remediation.executed.forEach(e => console.log("-", e));
}

if (STRIP_PATHS) {
  applyPathStripping(report, target, repoName);
}

fs.writeFileSync(outputFile, JSON.stringify(report, null, 2));

const htmlFile = path.join(outputDir, `${repoName}.html`);
fs.writeFileSync(htmlFile, renderHtml(report, repoName));

console.log("\nReport saved:", outputFile);
console.log("HTML report:", htmlFile);

if (EMIT_SARIF) {
  const sarifFile = path.join(outputDir, `${repoName}.sarif.json`);
  const sarif = buildSarif(report, repoName, target);
  fs.writeFileSync(sarifFile, JSON.stringify(sarif, null, 2));
  console.log("SARIF report:", sarifFile);
}

process.exit(report.status === "PASS" ? 0 : 1);
