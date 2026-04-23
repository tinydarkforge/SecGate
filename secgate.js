#!/usr/bin/env node

import { execSync } from "child_process";
import fs from "fs";
import path from "path";

/* -----------------------------
   CONFIG
------------------------------*/

const target = process.argv[2] || ".";
const APPLY = process.argv.includes("--apply");
const DEBUG = process.argv.includes("--debug");

const outputFile = "secgate-v7-report.json";

/* -----------------------------
   STATE
------------------------------*/

const findings = [];

const report = {
  version: "7.0",
  timestamp: new Date().toISOString(),
  target,
  mode: APPLY ? "apply" : "dry-run",
  status: "PASS",

  summary: { critical: 0, high: 0, medium: 0, low: 0 },

  findings: [],

  intelligence: {
    riskScore: 0,
    attackSurface: [],
    reasoning: [],
    recommendations: []
  },

  remediation: {
    plan: [],
    stagedChanges: [],
    executed: [],
    blocked: [],
    confidence: 100
  }
};

/* -----------------------------
   UTILS
------------------------------*/

function run(cmd) {
  try {
    return execSync(cmd, { encoding: "utf-8", stdio: "pipe" });
  } catch (e) {
    return ((e.stdout || "") + (e.stderr || "")).toString();
  }
}

function toolExists(cmd) {
  try {
    execSync(`which ${cmd}`, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function debug(label, data) {
  if (DEBUG) {
    console.log(`\n[DEBUG] ${label}`);
    console.log(data.slice(0, 1000));
  }
}

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
   SCANNERS (REAL JSON PARSING)
------------------------------*/

function gitleaks() {
  if (!toolExists("gitleaks")) return;

  const out = run(`gitleaks detect --source ${target} --report-format json`);
  debug("gitleaks", out);

  try {
    const data = JSON.parse(out);

    data.forEach(item => {
      addFinding({
        tool: "gitleaks",
        type: "secret",
        severity: "CRITICAL",
        signature: item.RuleID,
        message: item.Description,
        fixable: false
      });
    });
  } catch {}
}

function semgrep() {
  if (!toolExists("semgrep")) return;

  const out = run(`semgrep --config=auto --json ${target}`);
  debug("semgrep", out);

  try {
    const data = JSON.parse(out);

    data.results.forEach(r => {
      addFinding({
        tool: "semgrep",
        type: "code",
        severity: r.extra.severity === "ERROR" ? "HIGH" : "MEDIUM",
        signature: r.check_id,
        message: r.extra.message,
        fixable: true
      });
    });
  } catch {}
}

function severityFromCvss(score) {
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  return "LOW";
}

function osvScanner() {
  if (!toolExists("osv-scanner")) return;

  const out = run(`osv-scanner --format json -r ${target}`);
  debug("osv-scanner", out);

  try {
    const data = JSON.parse(out);
    const results = data.results || [];

    for (const r of results) {
      for (const p of r.packages || []) {
        const pkgName = p.package?.name || "unknown";
        const pkgEco = p.package?.ecosystem || "unknown";

        for (const v of p.vulnerabilities || []) {
          const cvss = (v.severity || [])
            .map(s => parseFloat(s.score?.match(/\d+\.\d+/)?.[0] || "0"))
            .reduce((a, b) => Math.max(a, b), 0);

          addFinding({
            tool: "osv",
            type: "dependency",
            severity: severityFromCvss(cvss),
            signature: `${pkgEco}:${pkgName}@${v.id}`,
            message: v.summary || v.id,
            fixable: true
          });
        }
      }
    }
  } catch {}
}

function trivy() {
  if (!toolExists("trivy")) return;

  const out = run(
    `trivy fs --quiet --format json --scanners misconfig,license ${target}`
  );
  debug("trivy", out);

  try {
    const data = JSON.parse(out);
    const results = data.Results || [];

    for (const r of results) {
      for (const m of r.Misconfigurations || []) {
        addFinding({
          tool: "trivy",
          type: "iac",
          severity: (m.Severity || "MEDIUM").toUpperCase(),
          signature: `${m.ID}:${r.Target}`,
          message: m.Title || m.Description || m.ID,
          fixable: false
        });
      }

      for (const l of r.Licenses || []) {
        addFinding({
          tool: "trivy",
          type: "license",
          severity: (l.Severity || "LOW").toUpperCase(),
          signature: `${l.Name}:${l.PkgName || r.Target}`,
          message: `License ${l.Name} flagged for ${l.PkgName || r.Target}`,
          fixable: false
        });
      }
    }
  } catch {}
}

function npmAudit() {
  if (!fs.existsSync(`${target}/package.json`)) return;

  const out = run(`cd ${target} && npm audit --json`);
  debug("npm audit", out);

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
        message: v.title,
        fixable: true
      });
    }
  } catch {}
}

/* -----------------------------
   INTELLIGENCE ENGINE
------------------------------*/

function analyze(findings) {
  let risk = 0;
  const surface = new Set();
  const reasoning = [];
  const recs = [];

  for (const f of findings) {
    const weight =
      f.severity === "CRITICAL"
        ? 10
        : f.severity === "HIGH"
        ? 6
        : f.severity === "MEDIUM"
        ? 3
        : 1;

    risk += weight;
    surface.add(f.type);

    reasoning.push({
      issue: f.signature,
      why:
        f.type === "secret"
          ? "Credential exposure enables immediate compromise"
          : f.type === "dependency"
          ? "Known CVEs can be exploited"
          : f.type === "iac"
          ? "Infrastructure misconfig expands attack surface"
          : f.type === "license"
          ? "License obligation or incompatibility risk"
          : "Unsafe code pattern"
    });

    if (f.type === "secret") recs.push("Rotate credentials immediately");
    if (f.type === "dependency") recs.push("Upgrade affected packages");
    if (f.type === "code") recs.push("Refactor insecure code");
    if (f.type === "iac") recs.push("Harden infrastructure configuration");
    if (f.type === "license") recs.push("Review third-party licenses");
  }

  return {
    riskScore: risk,
    attackSurface: [...surface],
    reasoning,
    recommendations: [...new Set(recs)]
  };
}

/* -----------------------------
   REMEDIATION ENGINE
------------------------------*/

function patch(f) {
  if (f.tool === "npm") {
    return {
      action: "npm audit fix",
      cmd: `cd ${target} && npm audit fix`
    };
  }

  if (f.tool === "semgrep") {
    return {
      action: "manual code fix",
      cmd: null
    };
  }

  if (f.tool === "gitleaks") {
    return {
      action: "remove + rotate secret",
      cmd: null
    };
  }

  if (f.tool === "osv") {
    return {
      action: "upgrade dependency",
      cmd: null
    };
  }

  if (f.tool === "trivy") {
    return {
      action: f.type === "license" ? "review license" : "fix misconfiguration",
      cmd: null
    };
  }

  return { action: "manual", cmd: null };
}

function remediate(findings) {
  let confidence = 100;
  const plan = [];
  const staged = [];
  const executed = [];
  const blocked = [];

  for (const f of findings) {
    const p = patch(f);

    plan.push({ issue: f.signature, patch: p });

    if (f.severity === "CRITICAL") {
      blocked.push(p);
      confidence -= 30;
      continue;
    }

    if (f.fixable && p.cmd) {
      staged.push(p);

      if (APPLY) {
        try {
          run(p.cmd);
          executed.push(p.action);
        } catch {
          blocked.push(p);
        }
      }
    }
  }

  return {
    plan,
    stagedChanges: staged,
    executed,
    blocked,
    confidence: Math.max(confidence, 0)
  };
}

/* -----------------------------
   HTML REPORT (PREMIUM)
------------------------------*/

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[c]));
}

function sevColor(sev) {
  return {
    CRITICAL: "#ff3b30",
    HIGH: "#ff9500",
    MEDIUM: "#ffcc00",
    LOW: "#34c759"
  }[sev] || "#8e8e93";
}

function renderHtml(rep, repoName) {
  const e = escapeHtml;
  const surfaces = rep.intelligence.attackSurface || [];
  const sum = rep.summary;

  const findingsRows = rep.findings
    .map(
      f => `
      <tr>
        <td><span class="pill" style="background:${sevColor(f.severity)}">${e(f.severity)}</span></td>
        <td>${e(f.tool)}</td>
        <td>${e(f.type)}</td>
        <td class="mono">${e(f.signature)}</td>
        <td>${e(f.message)}</td>
        <td>${f.fixable ? "yes" : "no"}</td>
      </tr>`
    )
    .join("");

  const reasoningCards = (rep.intelligence.reasoning || [])
    .map(
      r => `
      <div class="card">
        <div class="card-title mono">${e(r.issue)}</div>
        <div class="card-body">${e(r.why)}</div>
      </div>`
    )
    .join("");

  const recList = (rep.intelligence.recommendations || [])
    .map(r => `<li>${e(r)}</li>`)
    .join("");

  const remedItems = (rep.remediation.plan || [])
    .map(
      p => `
      <li>
        <span class="mono">${e(p.issue)}</span> — ${e(p.patch?.action || "manual")}
        ${p.patch?.cmd ? `<code class="cmd">${e(p.patch.cmd)}</code>` : ""}
      </li>`
    )
    .join("");

  const surfaceChips = surfaces
    .map(s => `<span class="chip">${e(s)}</span>`)
    .join("");

  const statusClr = rep.status === "PASS" ? "#34c759" : "#ff3b30";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecGate Report — ${e(repoName)}</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 32px;
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #0a0a0a; color: #e5e5e7;
  }
  .wrap { max-width: 1200px; margin: 0 auto; }
  header {
    display: flex; justify-content: space-between; align-items: center;
    padding-bottom: 24px; border-bottom: 1px solid #1f1f1f; margin-bottom: 32px;
  }
  h1 { font-size: 24px; margin: 0; font-weight: 600; letter-spacing: -0.02em; }
  h1 .sub { color: #8e8e93; font-weight: 400; font-size: 14px; margin-left: 8px; }
  h2 { font-size: 16px; margin: 32px 0 12px; font-weight: 600; letter-spacing: -0.01em; }
  .badge {
    padding: 6px 14px; border-radius: 999px; font-weight: 600; font-size: 12px;
    color: #0a0a0a;
  }
  .kpis { display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin: 24px 0; }
  .kpi {
    background: #141414; border: 1px solid #1f1f1f; border-radius: 12px;
    padding: 16px; text-align: center;
  }
  .kpi .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: #8e8e93; }
  .kpi .value { font-size: 24px; font-weight: 600; margin-top: 4px; letter-spacing: -0.02em; }
  .chip {
    display: inline-block; padding: 4px 10px; margin: 2px; border-radius: 999px;
    background: #1f1f1f; color: #e5e5e7; font-size: 12px;
  }
  table { width: 100%; border-collapse: collapse; margin-top: 8px; }
  th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #1f1f1f; vertical-align: top; }
  th { color: #8e8e93; font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 4px; color: #0a0a0a; font-size: 11px; font-weight: 700; }
  .mono { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 12px; color: #a5a5aa; }
  .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; }
  .card { background: #141414; border: 1px solid #1f1f1f; border-radius: 12px; padding: 14px; }
  .card-title { font-size: 12px; margin-bottom: 6px; }
  .card-body { font-size: 13px; color: #c7c7cc; }
  ul { margin: 8px 0; padding-left: 18px; }
  li { margin: 4px 0; }
  code.cmd { display: inline-block; padding: 2px 6px; margin-left: 8px; background: #1f1f1f; border-radius: 4px; font-size: 11px; }
  footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid #1f1f1f; color: #8e8e93; font-size: 12px; text-align: center; }
  .empty { color: #8e8e93; font-style: italic; padding: 12px 0; }
</style>
</head>
<body>
<div class="wrap">

  <header>
    <h1>SecGate <span class="sub">${e(repoName)}</span></h1>
    <span class="badge" style="background:${statusClr}">${e(rep.status)}</span>
  </header>

  <div class="mono">
    scanned ${e(rep.timestamp)} · target <b>${e(rep.target)}</b> · mode <b>${e(rep.mode)}</b>
  </div>

  <h2>Executive summary</h2>
  <div class="kpis">
    <div class="kpi"><div class="label">Risk</div><div class="value">${e(rep.intelligence.riskScore)}</div></div>
    <div class="kpi"><div class="label">Confidence</div><div class="value">${e(rep.remediation.confidence)}%</div></div>
    <div class="kpi"><div class="label">Critical</div><div class="value" style="color:${sevColor("CRITICAL")}">${e(sum.critical)}</div></div>
    <div class="kpi"><div class="label">High</div><div class="value" style="color:${sevColor("HIGH")}">${e(sum.high)}</div></div>
    <div class="kpi"><div class="label">Medium</div><div class="value" style="color:${sevColor("MEDIUM")}">${e(sum.medium)}</div></div>
    <div class="kpi"><div class="label">Low</div><div class="value" style="color:${sevColor("LOW")}">${e(sum.low)}</div></div>
  </div>

  <h2>Attack surface</h2>
  <div>${surfaceChips || '<span class="empty">Nothing detected.</span>'}</div>

  <h2>Findings (${rep.findings.length})</h2>
  ${
    rep.findings.length
      ? `<table>
    <thead><tr><th>Severity</th><th>Tool</th><th>Type</th><th>Signature</th><th>Message</th><th>Fixable</th></tr></thead>
    <tbody>${findingsRows}</tbody>
  </table>`
      : '<div class="empty">Clean. No findings.</div>'
  }

  <h2>Reasoning</h2>
  ${reasoningCards ? `<div class="cards">${reasoningCards}</div>` : '<div class="empty">No reasoning produced.</div>'}

  <h2>Recommendations</h2>
  ${recList ? `<ul>${recList}</ul>` : '<div class="empty">No recommendations.</div>'}

  <h2>Remediation plan</h2>
  ${remedItems ? `<ul>${remedItems}</ul>` : '<div class="empty">No plan items.</div>'}

  <footer>
    SecGate v${e(rep.version)} · MIT · TinyDarkForge
  </footer>

</div>
</body>
</html>`;
}

/* -----------------------------
   PIPELINE
------------------------------*/

console.log("\nSEC GATE v7 - AI SOC ENGINE");
console.log("Target:", target);
console.log("Mode:", APPLY ? "APPLY" : "DRY RUN");
console.log("--------------------------------");

semgrep();
gitleaks();
npmAudit();
osvScanner();
trivy();

/* -----------------------------
   PROCESS
------------------------------*/

report.findings = findings;

for (const f of findings) {
  report.summary[f.severity.toLowerCase()]++;
}

report.intelligence = analyze(findings);
report.remediation = remediate(findings);

/* -----------------------------
   DECISION
------------------------------*/

const hasCritical = findings.some(f => f.severity === "CRITICAL");
const hasHigh = findings.some(f => f.severity === "HIGH");

report.status = hasCritical || hasHigh ? "FAIL" : "PASS";

/* -----------------------------
   OUTPUT
------------------------------*/

console.log("\n--------------------------------");
console.log("STATUS:", report.status);
console.log("RISK SCORE:", report.intelligence.riskScore);
console.log("CONFIDENCE:", report.remediation.confidence + "%");

console.log("\nTOP ISSUES:");
findings.slice(0, 5).forEach(f =>
  console.log("-", f.signature, "|", f.severity)
);

console.log("\nRECOMMENDATIONS:");
report.intelligence.recommendations.forEach(r =>
  console.log("-", r)
);

if (APPLY) {
  console.log("\nEXECUTED FIXES:");
  report.remediation.executed.forEach(e => console.log("-", e));
}

fs.writeFileSync(outputFile, JSON.stringify(report, null, 2));

const repoName = path.basename(path.resolve(target));
const htmlFile = `${repoName}.html`;
fs.writeFileSync(htmlFile, renderHtml(report, repoName));

console.log("\nReport saved:", outputFile);
console.log("HTML report:", htmlFile);

process.exit(report.status === "PASS" ? 0 : 1);