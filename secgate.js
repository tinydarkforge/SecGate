#!/usr/bin/env node

import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(
  fs.readFileSync(path.join(__dirname, "package.json"), "utf-8")
);

/* -----------------------------
   CONFIG
------------------------------*/

const argv = process.argv.slice(2);

if (argv.includes("--version") || argv.includes("-v")) {
  console.log(pkg.version);
  process.exit(0);
}

if (argv.includes("--help") || argv.includes("-h")) {
  console.log(`SecGate v${pkg.version} — tiny security gate for CI/CD

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
  --debug             Print raw scanner output
  --version, -v       Print version and exit
  --help, -h          Show this help

Environment:
  SECGATE_CONFIRM_APPLY=1   Non-interactive confirmation for --apply
  CI=true                   Auto-enables --strip-paths

Exit codes:
  0  PASS — no CRITICAL or HIGH findings
  1  FAIL — CRITICAL or HIGH findings present
  2  Invalid target or CLI error

Output:
  secgate-v7-report.json    machine-readable report
  <repo-name>.html          premium HTML report
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

const rawTarget = argv[0] && !argv[0].startsWith("--") ? argv[0] : ".";
const APPLY = argv.includes("--apply");
const DEBUG = argv.includes("--debug");
const STRIP_PATHS = argv.includes("--strip-paths") || process.env.CI === "true";
const OUTPUT_DIR_FLAG = argValue("--output-dir");

const target = path.resolve(rawTarget);

if (!fs.existsSync(target)) {
  console.error(`Target not found: ${rawTarget}`);
  process.exit(2);
}
if (!fs.statSync(target).isDirectory()) {
  console.error(`Target is not a directory: ${rawTarget}`);
  process.exit(2);
}

const outputDir = OUTPUT_DIR_FLAG
  ? path.resolve(OUTPUT_DIR_FLAG)
  : target;

if (!OUTPUT_DIR_FLAG) {
  // Default output must live under the target — never leak to cwd.
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

const repoName = path.basename(path.resolve(target));
const reportTarget = STRIP_PATHS ? repoName : target;

const outputFile = path.join(outputDir, "secgate-v7-report.json");

/* -----------------------------
   STATE
------------------------------*/

const findings = [];

const TOOLS = ["semgrep", "gitleaks", "npm", "osv", "trivy"];

const toolStatus = {
  semgrep: "pending",
  gitleaks: "pending",
  npm: "pending",
  osv: "pending",
  trivy: "pending"
};

const toolSkipReason = {};

const report = {
  version: pkg.version,
  timestamp: new Date().toISOString(),
  target: reportTarget,
  mode: APPLY ? "apply" : "dry-run",
  status: "PASS",

  summary: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },

  findings: [],
  tools: toolStatus,
  toolSkipReason,

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
  },

  auditLog: []
};

function auditLog(event, detail) {
  const entry = {
    timestamp: new Date().toISOString(),
    event,
    target: reportTarget,
    ...detail
  };
  report.auditLog.push(entry);
  console.error(`[audit] ${JSON.stringify(entry)}`);
}

function stripAbsolutePaths(s) {
  if (!STRIP_PATHS || typeof s !== "string") return s;
  // Replace any occurrence of the absolute target path with the repo basename.
  const abs = target;
  let out = s.split(abs).join(repoName);
  // Also scrub parent dir paths that might appear via tools.
  const parent = path.dirname(abs);
  if (parent && parent !== "/" && parent !== ".") {
    out = out.split(parent + path.sep).join("");
  }
  return out;
}

/* -----------------------------
   UTILS
------------------------------*/

function runTool(binary, args, opts = {}) {
  try {
    return execFileSync(binary, args, {
      encoding: "utf-8",
      stdio: "pipe",
      maxBuffer: 64 * 1024 * 1024,
      ...opts
    });
  } catch (e) {
    return ((e.stdout || "") + (e.stderr || "")).toString();
  }
}

function toolExists(cmd) {
  try {
    execFileSync("which", [cmd], { stdio: "ignore" });
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

const SEVERITY_TIERS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

function normalizeSeverity(raw) {
  if (raw == null) return "UNKNOWN";
  const v = String(raw).trim().toUpperCase();
  if (v === "MODERATE") return "MEDIUM";
  if (v === "WARNING") return "MEDIUM";
  if (v === "ERROR") return "HIGH";
  if (v === "INFO" || v === "NOTE" || v === "INFORMATIONAL") return "LOW";
  if (v === "NEGLIGIBLE") return "LOW";
  return SEVERITY_TIERS.includes(v) ? v : "UNKNOWN";
}

function addFinding(f) {
  const severity = normalizeSeverity(f.severity);
  const fixableBy =
    f.fixableBy === "auto" || f.fixableBy === "manual"
      ? f.fixableBy
      : f.fixable
      ? "manual"
      : null;

  findings.push({
    tool: f.tool,
    type: f.type,
    severity,
    signature: f.signature,
    message: f.message,
    file: f.file ?? null,
    line: f.line ?? null,
    col: f.col ?? null,
    endLine: f.endLine ?? null,
    fixable: fixableBy === "auto",
    fixableBy
  });
}

/* -----------------------------
   SCANNERS (REAL JSON PARSING)
------------------------------*/

function gitleaks() {
  if (!toolExists("gitleaks")) { toolStatus.gitleaks = "skipped"; toolSkipReason.gitleaks = "not installed"; return; }

  const out = runTool("gitleaks", [
    "detect",
    "--source", target,
    "--report-format", "json"
  ]);
  debug("gitleaks", out);

  if (!out.trim()) { toolStatus.gitleaks = "clean"; return; }

  try {
    const data = JSON.parse(out);
    const before = findings.length;

    data.forEach(item => {
      addFinding({
        tool: "gitleaks",
        type: "secret",
        severity: "CRITICAL",
        signature: item.RuleID,
        message: item.Description,
        file: item.File ?? null,
        line: item.StartLine ?? null,
        endLine: item.EndLine ?? null,
        fixableBy: "manual"
      });
    });

    toolStatus.gitleaks = findings.length > before ? "ran" : "clean";
  } catch {
    toolStatus.gitleaks = "error";
  }
}

const SEMGREP_TIER = {
  ERROR: "HIGH",
  WARNING: "MEDIUM",
  INFO: "LOW",
  NOTE: "LOW"
};

const SECRET_RE = /(secret|credential|password|token|api[_-]?key|hardcoded)/i;
const SECRET_CWES = ["CWE-798", "CWE-259", "CWE-321", "CWE-522", "CWE-798:"];

function semgrepSeverity(r) {
  const base = SEMGREP_TIER[(r.extra?.severity || "").toUpperCase()] || "MEDIUM";

  const meta = r.extra?.metadata || {};
  const category = String(meta.category || "").toLowerCase();
  const checkId = String(r.check_id || "");
  const cweArr = []
    .concat(meta.cwe || [])
    .concat(meta.owasp || [])
    .map(x => String(x));

  const isSecret =
    (category === "security" && SECRET_RE.test(checkId + " " + JSON.stringify(meta))) ||
    cweArr.some(c => SECRET_CWES.some(sc => c.toUpperCase().includes(sc)));

  return isSecret ? "CRITICAL" : base;
}

function semgrep() {
  if (!toolExists("semgrep")) { toolStatus.semgrep = "skipped"; toolSkipReason.semgrep = "not installed"; return; }

  const out = runTool("semgrep", [
    "--config=auto",
    "--json",
    target
  ]);
  debug("semgrep", out);

  try {
    const data = JSON.parse(out);
    const before = findings.length;

    data.results.forEach(r => {
      addFinding({
        tool: "semgrep",
        type: "code",
        severity: semgrepSeverity(r),
        signature: r.check_id,
        message: r.extra?.message,
        file: r.path ?? null,
        line: r.start?.line ?? null,
        col: r.start?.col ?? null,
        endLine: r.end?.line ?? null,
        fixableBy: "manual"
      });
    });

    toolStatus.semgrep = findings.length > before ? "ran" : "clean";
  } catch {
    toolStatus.semgrep = "error";
  }
}

function severityFromCvss(score) {
  if (!Number.isFinite(score) || score <= 0) return null;
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  return "LOW";
}

function cvssBaseScore(vec) {
  // OSV stores either a bare vector ("CVSS:3.1/AV:N/...") with no score,
  // or a prefixed score ("7.5/CVSS:3.1/..."). Strip the CVSS version prefix
  // first so we don't mistake "3.1" for the base score.
  const stripped = String(vec || "").replace(/CVSS:\d+\.\d+\/?/, "");
  const m = stripped.match(/(?:^|[^\d])(\d+(?:\.\d+)?)/);
  return m ? parseFloat(m[1]) : NaN;
}

function ratingFromText(txt) {
  const s = String(txt || "").toUpperCase();
  if (/\bCRITICAL\b/.test(s)) return "CRITICAL";
  if (/\bHIGH\b/.test(s)) return "HIGH";
  if (/\b(MODERATE|MEDIUM)\b/.test(s)) return "MEDIUM";
  if (/\bLOW\b/.test(s)) return "LOW";
  return null;
}

function osvSeverity(v) {
  // 1. CVSS numeric score — prefer V3, fall back to V2.
  const sev = v.severity || [];
  let best = 0;
  for (const s of sev) {
    const t = (s.type || "").toUpperCase();
    if (t === "CVSS_V3" || t === "CVSS_V2") {
      const score = cvssBaseScore(s.score);
      if (Number.isFinite(score)) best = Math.max(best, score);
    }
  }
  const bySeverity = severityFromCvss(best);
  if (bySeverity) return bySeverity;

  // 2. database_specific.severity rating string
  const dbSev = v.database_specific?.severity;
  const byDb = ratingFromText(dbSev);
  if (byDb) return byDb;

  // 3. Any rating text on severity entries
  for (const s of sev) {
    const byText = ratingFromText(s.type) || ratingFromText(s.score);
    if (byText) return byText;
  }

  // 4. Advisory body / details as last resort.
  const byDetails = ratingFromText(v.details);
  if (byDetails) return byDetails;

  return "UNKNOWN";
}

function osvScanner() {
  if (!toolExists("osv-scanner")) { toolStatus.osv = "skipped"; toolSkipReason.osv = "not installed"; return; }

  const out = runTool("osv-scanner", [
    "--format", "json",
    "-r", target
  ]);
  debug("osv-scanner", out);

  if (!out.trim() || /No package sources found/i.test(out)) {
    toolStatus.osv = "clean";
    return;
  }

  try {
    const data = JSON.parse(out);
    const results = data.results || [];
    const before = findings.length;

    for (const r of results) {
      const lockFile = r.source?.path || null;

      for (const p of r.packages || []) {
        const pkgName = p.package?.name || "unknown";
        const pkgEco = p.package?.ecosystem || "unknown";

        for (const v of p.vulnerabilities || []) {
          addFinding({
            tool: "osv",
            type: "dependency",
            severity: osvSeverity(v),
            signature: `${pkgEco}:${pkgName}@${v.id}`,
            message: v.summary || v.id,
            file: lockFile || pkgName,
            line: null,
            fixableBy: "manual"
          });
        }
      }
    }

    toolStatus.osv = findings.length > before ? "ran" : "clean";
  } catch {
    toolStatus.osv = "error";
  }
}

function trivy() {
  if (!toolExists("trivy")) { toolStatus.trivy = "skipped"; toolSkipReason.trivy = "not installed"; return; }

  const out = runTool("trivy", [
    "fs",
    "--quiet",
    "--format", "json",
    "--scanners", "misconfig,license",
    "--skip-dirs", "**/test/fixtures",
    "--skip-dirs", "**/node_modules",
    target
  ]);
  debug("trivy", out);

  try {
    const data = JSON.parse(out);
    const results = data.Results || [];
    const before = findings.length;

    for (const r of results) {
      for (const m of r.Misconfigurations || []) {
        addFinding({
          tool: "trivy",
          type: "iac",
          severity: m.Severity,
          signature: `${m.ID}:${r.Target}`,
          message: m.Title || m.Description || m.ID,
          file: r.Target ?? null,
          line: m.CauseMetadata?.StartLine ?? null,
          endLine: m.CauseMetadata?.EndLine ?? null,
          fixableBy: "manual"
        });
      }

      for (const l of r.Licenses || []) {
        addFinding({
          tool: "trivy",
          type: "license",
          severity: l.Severity,
          signature: `${l.Name}:${l.PkgName || r.Target}`,
          message: `License ${l.Name} flagged for ${l.PkgName || r.Target}`,
          file: l.FilePath || r.Target || null,
          line: null,
          fixableBy: "manual"
        });
      }
    }

    toolStatus.trivy = findings.length > before ? "ran" : "clean";
  } catch {
    toolStatus.trivy = "error";
  }
}

function npmAudit() {
  if (!fs.existsSync(path.join(target, "package.json"))) {
    toolStatus.npm = "skipped";
    toolSkipReason.npm = "no package.json in target";
    return;
  }

  const out = runTool("npm", ["audit", "--json"], { cwd: target });
  debug("npm audit", out);

  const jsonStart = out.indexOf("{");
  const jsonEnd = out.lastIndexOf("}");
  const cleanOut =
    jsonStart >= 0 && jsonEnd > jsonStart
      ? out.slice(jsonStart, jsonEnd + 1)
      : out;

  try {
    const json = JSON.parse(cleanOut);

    if (json.error) {
      if (json.error.code === "ENOLOCK") {
        toolStatus.npm = "skipped";
        toolSkipReason.npm = "no package-lock.json (run `npm install` to generate)";
      } else {
        toolStatus.npm = "error";
      }
      return;
    }

    const vulns = json.vulnerabilities || {};
    const before = findings.length;

    const lockFile = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock"]
      .find(f => fs.existsSync(path.join(target, f))) || "package.json";

    for (const k in vulns) {
      const v = vulns[k];

      addFinding({
        tool: "npm",
        type: "dependency",
        severity: v.severity,
        signature: k,
        message: v.title || v.name || k,
        file: lockFile,
        line: null,
        fixableBy: "auto"
      });
    }

    toolStatus.npm = findings.length > before ? "ran" : "clean";
  } catch {
    toolStatus.npm = "error";
  }
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
        : f.severity === "LOW"
        ? 1
        : 0;

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
      cmd: `npm audit fix --ignore-scripts (cwd=${reportTarget})`,
      exec: {
        binary: "npm",
        args: ["audit", "fix", "--ignore-scripts"],
        cwd: target
      }
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

    if (f.fixable && p.exec) {
      staged.push(p);

      if (APPLY) {
        auditLog("apply_exec", {
          tool: f.tool,
          signature: f.signature,
          binary: p.exec.binary,
          args: p.exec.args,
          cwd: p.exec.cwd
        });
        try {
          runTool(p.exec.binary, p.exec.args, {
            cwd: p.exec.cwd,
            env: { ...process.env, npm_config_ignore_scripts: "true" }
          });
          executed.push(p.action);
          auditLog("apply_ok", {
            tool: f.tool,
            signature: f.signature
          });
        } catch (e) {
          blocked.push(p);
          auditLog("apply_fail", {
            tool: f.tool,
            signature: f.signature,
            error: String(e && e.message ? e.message : e)
          });
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
    LOW: "#34c759",
    UNKNOWN: "#8e8e93"
  }[sev] || "#8e8e93";
}

function formatLocation(f) {
  if (!f.file) return "";
  const rel = f.file;
  const lineFrag = f.line != null ? `:${f.line}` : "";
  const colFrag = f.col != null ? `:${f.col}` : "";
  const label = `${rel}${lineFrag}${colFrag}`;
  // file:// link only when we have an absolute-looking path
  const isAbs = rel.startsWith("/") || /^[a-zA-Z]:[\\/]/.test(rel);
  if (isAbs) {
    const href = `file://${rel}${f.line != null ? `#L${f.line}` : ""}`;
    return `<a href="${escapeHtml(href)}" class="loc">${escapeHtml(label)}</a>`;
  }
  return `<span class="loc">${escapeHtml(label)}</span>`;
}

function renderHtml(rep, repoName) {
  const e = escapeHtml;
  const surfaces = rep.intelligence.attackSurface || [];
  const sum = rep.summary;
  const tools = rep.tools || {};

  const TOOL_ORDER = ["semgrep", "gitleaks", "npm", "osv", "trivy"];
  const TOOL_LABEL = {
    semgrep: "Semgrep",
    gitleaks: "Gitleaks",
    npm: "npm audit",
    osv: "osv-scanner",
    trivy: "Trivy"
  };

  const byTool = Object.fromEntries(TOOL_ORDER.map(t => [t, []]));
  for (const f of rep.findings) if (byTool[f.tool]) byTool[f.tool].push(f);

  const statusBadge = st => {
    const map = {
      ran: { text: "found issues", color: "#ff9500" },
      clean: { text: "clean", color: "#34c759" },
      skipped: { text: "skipped", color: "#8e8e93" },
      error: { text: "error parsing output", color: "#ff3b30" },
      pending: { text: "not run", color: "#8e8e93" }
    };
    const s = map[st] || map.pending;
    return `<span class="tool-badge" style="background:${s.color}">${e(s.text)}</span>`;
  };

  const rowsFor = list =>
    list
      .map(
        f => `
        <tr>
          <td><span class="pill" style="background:${sevColor(f.severity)}">${e(f.severity)}</span></td>
          <td>${e(f.type)}</td>
          <td class="mono">${e(f.signature)}</td>
          <td class="mono">${formatLocation(f) || '<span class="empty">—</span>'}</td>
          <td>${e(f.message)}</td>
          <td>${f.fixableBy === "auto" ? "auto" : f.fixableBy === "manual" ? "manual" : "no"}</td>
        </tr>`
      )
      .join("");

  const panelBody = tool => {
    const st = tools[tool] || "pending";
    const list = byTool[tool] || [];

    if (st === "skipped") {
      const reason = rep.toolSkipReason?.[tool] || "not installed";
      return `<div class="empty">${e(TOOL_LABEL[tool])} skipped — ${e(reason)}.</div>`;
    }
    if (st === "error") {
      return `<div class="empty">${e(TOOL_LABEL[tool])} ran but output could not be parsed. Re-run with <code>--debug</code> to inspect.</div>`;
    }
    if (st === "pending") {
      return `<div class="empty">${e(TOOL_LABEL[tool])} did not run (target not applicable).</div>`;
    }
    if (!list.length) {
      return `<div class="empty success">${e(TOOL_LABEL[tool])} scanned the target and found no issues.</div>`;
    }
    return `<table>
      <thead><tr><th>Severity</th><th>Type</th><th>Signature</th><th>Location</th><th>Message</th><th>Fixable</th></tr></thead>
      <tbody>${rowsFor(list)}</tbody>
    </table>`;
  };

  const firstTool = TOOL_ORDER[0];
  const tabInputs = TOOL_ORDER
    .map(
      t => `<input type="radio" name="tabs" id="tab-${t}" class="tab-radio"${t === firstTool ? " checked" : ""}>`
    )
    .join("");

  const tabLabels = TOOL_ORDER
    .map(t => {
      const count = byTool[t].length;
      const st = tools[t] || "pending";
      return `<label for="tab-${t}" class="tab-label">
        <span>${e(TOOL_LABEL[t])}</span>
        ${count ? `<span class="tab-count">${count}</span>` : ""}
        ${statusBadge(st)}
      </label>`;
    })
    .join("");

  const tabPanels = TOOL_ORDER
    .map(
      t => `<div class="tab-panel" data-tool="${t}">${panelBody(t)}</div>`
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
  .kpis { display: grid; grid-template-columns: repeat(7, 1fr); gap: 12px; margin: 24px 0; }
  .loc { color: #9ad3ff; text-decoration: none; }
  .loc:hover { text-decoration: underline; }
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
  .empty.success { color: #34c759; }

  .tabs { margin-top: 8px; }
  .tab-radio { position: absolute; opacity: 0; pointer-events: none; }
  .tab-bar { display: flex; flex-wrap: wrap; gap: 4px; border-bottom: 1px solid #1f1f1f; margin-bottom: 16px; }
  .tab-label {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 10px 14px; cursor: pointer; color: #8e8e93;
    border-bottom: 2px solid transparent; margin-bottom: -1px;
    font-size: 13px; font-weight: 500;
    transition: color .15s, border-color .15s;
  }
  .tab-label:hover { color: #e5e5e7; }
  .tab-count {
    display: inline-block; min-width: 20px; padding: 1px 6px;
    background: #1f1f1f; border-radius: 10px; font-size: 11px;
    color: #e5e5e7; text-align: center;
  }
  .tool-badge {
    display: inline-block; padding: 2px 8px; border-radius: 999px;
    font-size: 10px; font-weight: 600; color: #0a0a0a;
    text-transform: uppercase; letter-spacing: 0.04em;
  }
  .tab-panels .tab-panel { display: none; }

  #tab-semgrep:checked  ~ .tab-bar label[for="tab-semgrep"],
  #tab-gitleaks:checked ~ .tab-bar label[for="tab-gitleaks"],
  #tab-npm:checked      ~ .tab-bar label[for="tab-npm"],
  #tab-osv:checked      ~ .tab-bar label[for="tab-osv"],
  #tab-trivy:checked    ~ .tab-bar label[for="tab-trivy"] {
    color: #e5e5e7; border-bottom-color: #e5e5e7;
  }
  #tab-semgrep:checked  ~ .tab-panels .tab-panel[data-tool="semgrep"],
  #tab-gitleaks:checked ~ .tab-panels .tab-panel[data-tool="gitleaks"],
  #tab-npm:checked      ~ .tab-panels .tab-panel[data-tool="npm"],
  #tab-osv:checked      ~ .tab-panels .tab-panel[data-tool="osv"],
  #tab-trivy:checked    ~ .tab-panels .tab-panel[data-tool="trivy"] {
    display: block;
  }

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
    <div class="kpi"><div class="label">Unknown</div><div class="value" style="color:${sevColor("UNKNOWN")}">${e(sum.unknown || 0)}</div></div>
  </div>

  <h2>Attack surface</h2>
  <div>${surfaceChips || '<span class="empty">Nothing detected.</span>'}</div>

  <h2>Findings by tool (${rep.findings.length} total)</h2>
  <div class="tabs">
    ${tabInputs}
    <div class="tab-bar">${tabLabels}</div>
    <div class="tab-panels">${tabPanels}</div>
  </div>

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
      const buf = Buffer.alloc(8);
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

console.log("\nSEC GATE v7 - AI SOC ENGINE");
console.log("Target:", reportTarget);
console.log("Mode:", APPLY ? "APPLY" : "DRY RUN");
console.log("--------------------------------");

confirmApplyOrExit();
if (APPLY) {
  auditLog("apply_start", { outputDir });
}

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
  const key = String(f.severity || "UNKNOWN").toLowerCase();
  if (Object.prototype.hasOwnProperty.call(report.summary, key)) {
    report.summary[key]++;
  } else {
    report.summary.unknown++;
  }
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

console.log("\nSCANNER STATUS:");
for (const t of TOOLS) {
  console.log(`- ${t.padEnd(10)} ${toolStatus[t]}`);
}

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

if (STRIP_PATHS) {
  for (const f of report.findings) {
    if (f.signature) f.signature = stripAbsolutePaths(f.signature);
    if (f.message) f.message = stripAbsolutePaths(f.message);
    if (f.file) f.file = stripAbsolutePaths(f.file);
  }
  for (const r of report.intelligence.reasoning || []) {
    if (r.issue) r.issue = stripAbsolutePaths(r.issue);
    if (r.why) r.why = stripAbsolutePaths(r.why);
  }
  for (const p of report.remediation.plan || []) {
    if (p.issue) p.issue = stripAbsolutePaths(p.issue);
    if (p.patch) {
      if (p.patch.cmd) p.patch.cmd = stripAbsolutePaths(p.patch.cmd);
      if (p.patch.exec && p.patch.exec.cwd) {
        p.patch.exec.cwd = stripAbsolutePaths(p.patch.exec.cwd);
      }
    }
  }
  for (const p of report.remediation.stagedChanges || []) {
    if (p.cmd) p.cmd = stripAbsolutePaths(p.cmd);
    if (p.exec && p.exec.cwd) p.exec.cwd = stripAbsolutePaths(p.exec.cwd);
  }
  for (const p of report.remediation.blocked || []) {
    if (p.cmd) p.cmd = stripAbsolutePaths(p.cmd);
    if (p.exec && p.exec.cwd) p.exec.cwd = stripAbsolutePaths(p.exec.cwd);
  }
  for (const a of report.auditLog || []) {
    if (a.cwd) a.cwd = stripAbsolutePaths(a.cwd);
  }
}

fs.writeFileSync(outputFile, JSON.stringify(report, null, 2));

const htmlFile = path.join(outputDir, `${repoName}.html`);
fs.writeFileSync(htmlFile, renderHtml(report, repoName));

console.log("\nReport saved:", outputFile);
console.log("HTML report:", htmlFile);

process.exit(report.status === "PASS" ? 0 : 1);