#!/usr/bin/env node

import { execSync } from "child_process";
import fs from "fs";

const target = process.argv[2] || ".";
const outputFile = "secgate-v2-report.json";

/* -----------------------------
   ENGINE STATE
------------------------------*/

let CRITICAL = 0;
let HIGH = 0;
let MEDIUM = 0;
let LOW = 0;

const report = {
  version: "2.0",
  timestamp: new Date().toISOString(),
  target,
  status: "PASS",
  score: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  },
  findings: []
};

/* -----------------------------
   UTILITIES
------------------------------*/

function toolExists(cmd) {
  try {
    execSync(`which ${cmd}`, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function addFinding(tool, severity, message) {
  const finding = {
    tool,
    severity,
    message: message.slice(0, 1500)
  };

  report.findings.push(finding);

  if (severity === "CRITICAL") CRITICAL++;
  if (severity === "HIGH") HIGH++;
  if (severity === "MEDIUM") MEDIUM++;
  if (severity === "LOW") LOW++;
}

function run(name, cmd, parser = null, critical = false) {
  console.log(`\n[RUN] ${name}`);
  console.log(`$ ${cmd}`);

  try {
    const out = execSync(cmd, {
      encoding: "utf-8",
      stdio: "pipe"
    });

    if (parser) {
      parser(out);
    }

    console.log(`[OK] ${name}`);
  } catch (err) {
    const msg =
      (err.stdout || "").toString() +
      (err.stderr || "").toString() +
      (err.message || "");

    console.log(`[FAIL] ${name}`);

    // default classification
    const severity = critical ? "CRITICAL" : "MEDIUM";

    addFinding(name, severity, msg);

    if (critical) {
      console.log("!! CRITICAL FAILURE DETECTED");
    }
  }
}

/* -----------------------------
   SCANNERS
------------------------------*/

function semgrepScan() {
  if (!toolExists("semgrep")) return;

  run(
    "semgrep",
    `semgrep --config=auto ${target}`,
    (out) => {
      if (out.includes("ERROR") || out.includes("HIGH")) {
        addFinding("semgrep", "HIGH", out);
      } else if (out.includes("WARNING")) {
        addFinding("semgrep", "MEDIUM", out);
      }
    },
    true // critical scanner
  );
}

function gitleaksScan() {
  if (!toolExists("gitleaks")) return;

  run(
    "gitleaks",
    `gitleaks detect --source ${target}`,
    (out) => {
      if (out.includes("leak")) {
        addFinding("gitleaks", "HIGH", out);
      }
    }
  );
}

function trivyScan() {
  if (!toolExists("trivy")) return;

  run("trivy", `trivy fs ${target}`, (out) => {
    if (out.includes("CRITICAL")) addFinding("trivy", "CRITICAL", out);
    else if (out.includes("HIGH")) addFinding("trivy", "HIGH", out);
    else if (out.includes("MEDIUM")) addFinding("trivy", "MEDIUM", out);
  });
}

function npmAudit() {
  if (!fs.existsSync(`${target}/package.json`)) return;

  run("npm-audit", `cd ${target} && npm audit --json`, (out) => {
    try {
      const json = JSON.parse(out);

      const vulns = json?.vulnerabilities || {};

      for (const k in vulns) {
        const v = vulns[k];
        if (v.severity === "critical") addFinding("npm", "CRITICAL", k);
        if (v.severity === "high") addFinding("npm", "HIGH", k);
        if (v.severity === "moderate") addFinding("npm", "MEDIUM", k);
      }
    } catch {
      addFinding("npm", "LOW", "audit parse failed");
    }
  });
}

function pipAudit() {
  if (!fs.existsSync(`${target}/requirements.txt`)) return;

  run("pip-audit", `pip-audit -r ${target}/requirements.txt`, (out) => {
    if (out.includes("HIGH")) addFinding("pip", "HIGH", out);
  });
}

/* -----------------------------
   PIPELINE
------------------------------*/

console.log("\nSEC GATE v2 ENGINE START");
console.log("Target:", target);
console.log("--------------------------------");

/* PHASE 1: STATIC ANALYSIS */
console.log("\n[PHASE 1] Static Analysis");
semgrepScan();

/* PHASE 2: SECRET DETECTION */
console.log("\n[PHASE 2] Secrets");
gitleaksScan();

/* PHASE 3: DEPENDENCIES */
console.log("\n[PHASE 3] Dependencies");
npmAudit();
pipAudit();

/* PHASE 4: INFRASTRUCTURE */
console.log("\n[PHASE 4] Infrastructure");
trivyScan();

/* -----------------------------
   FINAL SCORING
------------------------------*/

report.score = {
  critical: CRITICAL,
  high: HIGH,
  medium: MEDIUM,
  low: LOW
};

report.status = CRITICAL > 0 || HIGH > 0 ? "FAIL" : "PASS";

/* -----------------------------
   OUTPUT
------------------------------*/

console.log("\n--------------------------------");
console.log("SEC GATE v2 COMPLETE");
console.log("STATUS:", report.status);

console.log("SCORE:", report.score);

fs.writeFileSync(outputFile, JSON.stringify(report, null, 2));

console.log("Report saved:", outputFile);

/* exit code for CI */
process.exit(report.status === "PASS" ? 0 : 1);