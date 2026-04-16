#!/usr/bin/env node

import { execSync } from "child_process";
import fs from "fs";

const target = process.argv[2] || ".";
const outputFile = "secgate-v3-report.json";

/* -----------------------------
   STATE
------------------------------*/

const findingsRaw = [];

const report = {
  version: "3.0",
  timestamp: new Date().toISOString(),
  target,
  status: "PASS",
  summary: {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  },
  findings: [],
  intelligence: {
    riskScore: 0,
    topRisks: [],
    attackSurface: [],
    recommendations: []
  }
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

function safeExec(name, cmd) {
  try {
    const out = execSync(cmd, { encoding: "utf-8", stdio: "pipe" });
    return out.toString();
  } catch (err) {
    return (err.stdout || "") + (err.stderr || "");
  }
}

/* -----------------------------
   NORMALIZED FINDING MODEL
------------------------------*/

function addFinding(f) {
  findingsRaw.push({
    id: `${f.tool}-${f.signature}`,
    tool: f.tool,
    type: f.type || "unknown",
    severity: f.severity || "LOW",
    message: f.message || "",
    asset: f.asset || target
  });
}

/* -----------------------------
   SCANNERS (RAW → NORMALIZED)
------------------------------*/

function semgrepScan() {
  if (!toolExists("semgrep")) return;

  const out = safeExec("semgrep", `semgrep --config=auto ${target}`);

  if (out.includes("ERROR") || out.includes("HIGH")) {
    addFinding({
      tool: "semgrep",
      signature: "generic",
      severity: "HIGH",
      type: "code",
      message: out.slice(0, 1500)
    });
  }
}

function gitleaksScan() {
  if (!toolExists("gitleaks")) return;

  const out = safeExec("gitleaks", `gitleaks detect --source ${target}`);

  if (out.includes("leak")) {
    addFinding({
      tool: "gitleaks",
      signature: "secret",
      severity: "CRITICAL",
      type: "secret",
      message: out.slice(0, 1500)
    });
  }
}

function trivyScan() {
  if (!toolExists("trivy")) return;

  const out = safeExec("trivy", `trivy fs ${target}`);

  if (out.includes("CRITICAL")) {
    addFinding({
      tool: "trivy",
      signature: "vuln-critical",
      severity: "CRITICAL",
      type: "dependency",
      message: out.slice(0, 1500)
    });
  } else if (out.includes("HIGH")) {
    addFinding({
      tool: "trivy",
      signature: "vuln-high",
      severity: "HIGH",
      type: "dependency",
      message: out.slice(0, 1500)
    });
  }
}

function npmAudit() {
  if (!fs.existsSync(`${target}/package.json`)) return;

  const out = safeExec("npm", `cd ${target} && npm audit --json`);

  try {
    const json = JSON.parse(out);
    const vulns = json.vulnerabilities || {};

    for (const k in vulns) {
      const v = vulns[k];

      addFinding({
        tool: "npm",
        signature: k,
        severity:
          v.severity === "critical"
            ? "CRITICAL"
            : v.severity === "high"
            ? "HIGH"
            : v.severity === "moderate"
            ? "MEDIUM"
            : "LOW",
        type: "dependency",
        message: k
      });
    }
  } catch {
    if (!out.includes("ENOLOCK")) {
      addFinding({
        tool: "npm",
        signature: "audit-failed",
        severity: "LOW",
        type: "tooling",
        message: "npm audit parse failed"
      });
    }
  }
}

/* -----------------------------
   DEDUP ENGINE (CORE v3 FEATURE)
------------------------------*/

function deduplicate(findings) {
  const map = new Map();

  for (const f of findings) {
    const key = `${f.tool}-${f.signature}`;

    if (!map.has(key)) {
      map.set(key, f);
    } else {
      // escalate severity if seen multiple times
      const existing = map.get(key);

      const rank = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

      if (rank[f.severity] > rank[existing.severity]) {
        existing.severity = f.severity;
      }
    }
  }

  return [...map.values()];
}

/* -----------------------------
   INTELLIGENCE ENGINE
------------------------------*/

function computeIntelligence(findings) {
  const severityWeight = {
    CRITICAL: 10,
    HIGH: 5,
    MEDIUM: 2,
    LOW: 1
  };

  let score = 0;

  const attackSurface = new Set();
  const recommendations = [];

  for (const f of findings) {
    score += severityWeight[f.severity] || 0;

    attackSurface.add(f.type);

    if (f.severity === "CRITICAL") {
      recommendations.push(`Fix critical issue in ${f.tool}`);
    }

    if (f.type === "secret") {
      recommendations.push("Rotate exposed secrets immediately");
    }

    if (f.type === "dependency") {
      recommendations.push("Update vulnerable dependencies");
    }
  }

  return {
    riskScore: score,
    attackSurface: [...attackSurface],
    recommendations: [...new Set(recommendations)]
  };
}

/* -----------------------------
   PIPELINE
------------------------------*/

console.log("\nSEC GATE v3 INTELLIGENCE ENGINE");
console.log("Target:", target);
console.log("--------------------------------");

semgrepScan();
gitleaksScan();
trivyScan();
npmAudit();

/* -----------------------------
   PROCESS FINDINGS
------------------------------*/

const deduped = deduplicate(findingsRaw);

/* summary */
for (const f of deduped) {
  report.summary.total++;

  if (f.severity === "CRITICAL") report.summary.critical++;
  if (f.severity === "HIGH") report.summary.high++;
  if (f.severity === "MEDIUM") report.summary.medium++;
  if (f.severity === "LOW") report.summary.low++;
}

report.findings = deduped;
report.intelligence = computeIntelligence(deduped);

/* -----------------------------
   FINAL STATUS
------------------------------*/

report.status =
  report.summary.critical > 0
    ? "FAIL"
    : report.summary.high > 0
    ? "FAIL"
    : "PASS";

/* -----------------------------
   OUTPUT
------------------------------*/

console.log("\n--------------------------------");
console.log("SEC GATE v3 COMPLETE");
console.log("STATUS:", report.status);

console.log("SUMMARY:", report.summary);
console.log("RISK SCORE:", report.intelligence.riskScore);

console.log("\nTOP RECOMMENDATIONS:");
report.intelligence.recommendations.forEach(r => console.log("-", r));

fs.writeFileSync(outputFile, JSON.stringify(report, null, 2));

console.log("\nReport saved:", outputFile);

process.exit(report.status === "PASS" ? 0 : 1);