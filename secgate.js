#!/usr/bin/env node

import { execSync } from "child_process";
import fs from "fs";

const target = process.argv[2] || ".";
const DEBUG = process.argv.includes("--debug");

const outputFile = "secgate-v5-report.json";

/* -----------------------------
   STATE
------------------------------*/

const findings = [];

const report = {
  version: "5.0",
  timestamp: new Date().toISOString(),
  target,
  status: "PASS",
  summary: { critical: 0, high: 0, medium: 0, low: 0 },

  findings: [],

  intelligence: {
    riskScore: 0,
    attackSurface: [],
    topRisks: [],
    reasoning: [],
    recommendations: []
  },

  actions: []
};

/* -----------------------------
   UTILS
------------------------------*/

function toolExists(cmd) {
  try {
    execSync(`which ${cmd}`, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function run(cmd) {
  try {
    return execSync(cmd, { encoding: "utf-8", stdio: "pipe" });
  } catch (e) {
    return ((e.stdout || "") + (e.stderr || "")).toString();
  }
}

function logDebug(label, data) {
  if (DEBUG) {
    console.log(`\n[DEBUG] ${label}`);
    console.log(data.slice(0, 1200));
  }
}

/* -----------------------------
   FINDINGS MODEL
------------------------------*/

function addFinding(f) {
  findings.push({
    tool: f.tool,
    type: f.type,
    severity: f.severity,
    signature: f.signature,
    message: f.message,
    fixable: f.fixable || false
  });
}

/* -----------------------------
   SCANNERS
------------------------------*/

function gitleaks() {
  if (!toolExists("gitleaks")) return;

  const out = run(`gitleaks detect --source ${target}`);
  logDebug("gitleaks", out);

  const low = out.toLowerCase();

  if (
    low.includes("leak") ||
    low.includes("secret") ||
    low.includes("finding")
  ) {
    addFinding({
      tool: "gitleaks",
      type: "secret",
      severity: "CRITICAL",
      signature: "secret-exposure",
      message: out.slice(0, 1200),
      fixable: false
    });
  }
}

function semgrep() {
  if (!toolExists("semgrep")) return;

  const out = run(`semgrep --config=auto ${target}`);
  logDebug("semgrep", out);

  const low = out.toLowerCase();

  if (low.includes("rule") || low.includes("warning") || low.includes("error")) {
    addFinding({
      tool: "semgrep",
      type: "code",
      severity: low.includes("error") ? "HIGH" : "MEDIUM",
      signature: "static-analysis",
      message: out.slice(0, 1200),
      fixable: true
    });
  }
}

function npmAudit() {
  if (!fs.existsSync(`${target}/package.json`)) return;

  const out = run(`cd ${target} && npm audit --json`);

  try {
    const json = JSON.parse(out);
    const vulns = json.vulnerabilities || {};

    for (const k in vulns) {
      const v = vulns[k];

      addFinding({
        tool: "npm",
        type: "dependency",
        severity:
          v.severity === "critical"
            ? "CRITICAL"
            : v.severity === "high"
            ? "HIGH"
            : "MEDIUM",
        signature: k,
        message: k,
        fixable: true
      });
    }
  } catch {}
}

/* -----------------------------
   AI REASONING ENGINE (v5 CORE)
------------------------------*/

function reason(f) {
  const map = {
    secret: {
      why: "Secrets can be immediately exploited for account takeover or cloud abuse.",
      exploit: "Direct credential reuse or API abuse is likely.",
      priority: 10
    },

    dependency: {
      why: "Vulnerable dependencies introduce known CVE-based attack vectors.",
      exploit: "Remote or local exploitation depends on exposure.",
      priority: 7
    },

    code: {
      why: "Unsafe code patterns can lead to injection or execution flaws.",
      exploit: "Depends on input reachability and execution path.",
      priority: 6
    }
  };

  return map[f.type] || {
    why: "Unknown risk type",
    exploit: "Unknown exploitability",
    priority: 1
  };
}

/* -----------------------------
   FIX SYNTHESIS ENGINE
------------------------------*/

function fix(f) {
  if (f.tool === "gitleaks") {
    return "Rotate credentials + remove secret from history (git filter-repo recommended)";
  }

  if (f.tool === "npm") {
    return "Run npm audit fix OR update affected packages manually";
  }

  if (f.tool === "semgrep") {
    return "Refactor unsafe pattern following secure coding guidelines";
  }

  return "Manual remediation required";
}

/* -----------------------------
   INTELLIGENCE ENGINE
------------------------------*/

function analyze(findings) {
  let risk = 0;

  const attackSurface = new Set();
  const reasoning = [];
  const recommendations = [];

  for (const f of findings) {
    const r = reason(f);

    const weight =
      f.severity === "CRITICAL"
        ? 10
        : f.severity === "HIGH"
        ? 5
        : 2;

    risk += weight + r.priority;
    attackSurface.add(f.type);

    reasoning.push({
      issue: f.signature,
      why: r.why,
      exploitability: r.exploit
    });

    if (f.severity === "CRITICAL") {
      recommendations.push(`IMMEDIATE: Fix ${f.tool} issue`);
    }

    if (f.type === "secret") {
      recommendations.push("Rotate all exposed credentials immediately");
    }

    if (f.type === "dependency") {
      recommendations.push("Patch vulnerable dependencies ASAP");
    }
  }

  return {
    riskScore: risk,
    attackSurface: [...attackSurface],
    reasoning,
    recommendations: [...new Set(recommendations)]
  };
}

/* -----------------------------
   ACTION ENGINE
------------------------------*/

function actions(findings) {
  return findings.map(f => ({
    tool: f.tool,
    severity: f.severity,
    fix: fix(f),
    autoExecutable: f.severity !== "CRITICAL"
  }));
}

/* -----------------------------
   PIPELINE
------------------------------*/

console.log("\nSEC GATE v5 AI SECURITY ENGINE");
console.log("Target:", target);
console.log("Debug:", DEBUG);
console.log("--------------------------------");

semgrep();
gitleaks();
npmAudit();

/* -----------------------------
   PROCESS
------------------------------*/

report.findings = findings;

/* summary */
for (const f of findings) {
  report.summary[f.severity.toLowerCase()]++;
}

/* intelligence */
report.intelligence = analyze(findings);

/* actions */
report.actions = actions(findings);

/* -----------------------------
   FINAL DECISION
------------------------------*/

const hasCritical = findings.some(f => f.severity === "CRITICAL");
const hasHigh = findings.some(f => f.severity === "HIGH");

report.status = hasCritical || hasHigh ? "FAIL" : "PASS";

/* -----------------------------
   OUTPUT
------------------------------*/

console.log("\n--------------------------------");
console.log("SEC GATE v5 COMPLETE");
console.log("STATUS:", report.status);

console.log("\nRISK SCORE:", report.intelligence.riskScore);

console.log("\nTOP REASONING:");
report.intelligence.reasoning.slice(0, 5).forEach(r => {
  console.log("-", r.why);
});

console.log("\nRECOMMENDATIONS:");
report.intelligence.recommendations.forEach(r => console.log("-", r));

console.log("\nACTIONS:");
report.actions.slice(0, 5).forEach(a => console.log("-", a.fix));

fs.writeFileSync(outputFile, JSON.stringify(report, null, 2));

console.log("\nReport saved:", outputFile);

process.exit(report.status === "PASS" ? 0 : 1);