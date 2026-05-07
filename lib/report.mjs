import { execFileSync } from "child_process";
import path from "path";

export const TOOLS = ["semgrep", "gitleaks", "npm", "osv", "trivy", "trivyImage"];

/**
 * Compute severity counts for a findings array.
 */
export function summarize(findings) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const f of findings) {
    const key = String(f.severity || "UNKNOWN").toLowerCase();
    if (Object.prototype.hasOwnProperty.call(summary, key)) {
      summary[key]++;
    } else {
      summary.unknown++;
    }
  }
  return summary;
}

/**
 * Determine PASS/FAIL status from findings and config.failOn set.
 */
export function resolveStatus(findings, failOn, baselineMode) {
  const failOnSet = new Set(failOn.map(s => s.toUpperCase()));
  const failFindings = baselineMode
    ? findings.filter(f => !f.baseline && failOnSet.has(f.severity))
    : findings.filter(f => failOnSet.has(f.severity));
  return failFindings.length > 0 ? "FAIL" : "PASS";
}

/**
 * Strip absolute paths from a string value, replacing with repoName.
 */
export function stripAbsolutePaths(s, target, repoName) {
  if (typeof s !== "string") return s;
  let out = s.split(target).join(repoName);
  const parent = path.dirname(target);
  if (parent && parent !== "/" && parent !== ".") {
    out = out.split(parent + path.sep).join("");
  }
  return out;
}

/**
 * Walk report fields and relativize all embedded absolute target paths.
 */
export function applyPathStripping(report, target, repoName) {
  const strip = s => stripAbsolutePaths(s, target, repoName);

  for (const f of report.findings) {
    if (f.signature) f.signature = strip(f.signature);
    if (f.message)   f.message   = strip(f.message);
    if (f.file)      f.file      = strip(f.file);
  }
  for (const r of report.intelligence.reasoning || []) {
    if (r.issue) r.issue = strip(r.issue);
    if (r.why)   r.why   = strip(r.why);
  }
  for (const p of report.remediation.plan || []) {
    if (p.issue) p.issue = strip(p.issue);
    if (p.patch) {
      if (p.patch.cmd) p.patch.cmd = strip(p.patch.cmd);
      if (p.patch.exec && p.patch.exec.cwd) p.patch.exec.cwd = strip(p.patch.exec.cwd);
    }
  }
  for (const p of report.remediation.stagedChanges || []) {
    if (p.cmd) p.cmd = strip(p.cmd);
    if (p.exec && p.exec.cwd) p.exec.cwd = strip(p.exec.cwd);
  }
  for (const p of report.remediation.blocked || []) {
    if (p.cmd) p.cmd = strip(p.cmd);
    if (p.exec && p.exec.cwd) p.exec.cwd = strip(p.exec.cwd);
  }
  for (const a of report.auditLog || []) {
    if (a.cwd) a.cwd = strip(a.cwd);
  }
}

/* ────────────────────────────────────────────────────────────────────────────
   HTML renderer
   ──────────────────────────────────────────────────────────────────────────── */

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
  const colFrag  = f.col  != null ? `:${f.col}`  : "";
  const label    = `${rel}${lineFrag}${colFrag}`;
  const isAbs = rel.startsWith("/") || /^[a-zA-Z]:[\\/]/.test(rel);
  if (isAbs) {
    const href = `file://${rel}${f.line != null ? `#L${f.line}` : ""}`;
    return `<a href="${escapeHtml(href)}" class="loc">${escapeHtml(label)}</a>`;
  }
  return `<span class="loc">${escapeHtml(label)}</span>`;
}

function bandFromScore(score) {
  if (score >= 85) return "strong";
  if (score >= 70) return "good";
  if (score >= 50) return "mixed";
  return "weak";
}

export function renderHtml(rep, repoName) {
  const e = escapeHtml;
  const surfaces = rep.intelligence.attackSurface || [];
  const sum      = rep.summary;
  const tools    = rep.tools || {};

  const TOOL_ORDER = ["semgrep", "gitleaks", "npm", "osv", "trivy"];
  const TOOL_LABEL = {
    semgrep:  "Semgrep",
    gitleaks: "Gitleaks",
    npm:      "npm audit",
    osv:      "osv-scanner",
    trivy:    "Trivy"
  };

  const byTool = Object.fromEntries(TOOL_ORDER.map(t => [t, []]));
  for (const f of rep.findings) if (byTool[f.tool]) byTool[f.tool].push(f);

  const statusPill = st => {
    const map = {
      ran:     { text: "found",   cls: "warn" },
      clean:   { text: "clean",   cls: "ok"   },
      skipped: { text: "skipped", cls: "" },
      error:   { text: "error",   cls: "risk" },
      pending: { text: "not run", cls: "" }
    };
    const s = map[st] || map.pending;
    return `<span class="sg-pill${s.cls ? ` sg-pill-${s.cls}` : ""}">${e(s.text)}</span>`;
  };

  const sevPill = sev => {
    const cls = { CRITICAL: "risk", HIGH: "risk", MEDIUM: "warn", LOW: "ok", UNKNOWN: "" }[sev] || "";
    return `<span class="sg-pill${cls ? ` sg-pill-${cls}` : ""}">${e(sev)}</span>`;
  };

  const rowsFor = list =>
    list
      .map(
        f => `
        <tr${f.baseline ? ' class="sg-baseline-row"' : ""}>
          <td>${sevPill(f.severity)}</td>
          <td>${e(f.type)}</td>
          <td class="sg-mono">${e(f.signature)}</td>
          <td class="sg-mono">${formatLocation(f) || '<span class="sg-empty">—</span>'}</td>
          <td>${e(f.message)}</td>
          <td>${f.fixableBy === "auto" ? "auto" : f.fixableBy === "manual" ? "manual" : "no"}</td>
          <td>${f.baseline ? '<span class="sg-bl-badge">baseline</span>' : ""}</td>
        </tr>`
      )
      .join("");

  const panelBody = tool => {
    const st   = tools[tool] || "pending";
    const list = byTool[tool] || [];

    if (st === "skipped") {
      const reason = rep.toolSkipReason?.[tool] || "not installed";
      return `<div class="sg-empty">${e(TOOL_LABEL[tool])} skipped — ${e(reason)}.</div>`;
    }
    if (st === "error") {
      return `<div class="sg-empty">${e(TOOL_LABEL[tool])} ran but output could not be parsed. Re-run with <code>--debug</code> to inspect.</div>`;
    }
    if (st === "pending") {
      return `<div class="sg-empty">${e(TOOL_LABEL[tool])} did not run (target not applicable).</div>`;
    }
    if (!list.length) {
      return `<div class="sg-empty sg-success">${e(TOOL_LABEL[tool])} scanned the target and found no issues.</div>`;
    }
    return `<table class="sg-table">
      <thead><tr><th>Severity</th><th>Type</th><th>Signature</th><th>Location</th><th>Message</th><th>Fixable</th><th>Baseline</th></tr></thead>
      <tbody>${rowsFor(list)}</tbody>
    </table>`;
  };

  const firstTool  = TOOL_ORDER[0];
  const tabInputs  = TOOL_ORDER
    .map(t => `<input type="radio" name="tabs" id="tab-${t}" class="sg-tab-radio"${t === firstTool ? " checked" : ""}>`)
    .join("");

  const tabLabels  = TOOL_ORDER
    .map(t => {
      const count = byTool[t].length;
      const st    = tools[t] || "pending";
      return `<label for="tab-${t}" class="sg-tab-label">
        <span>${e(TOOL_LABEL[t])}</span>
        ${count ? `<span class="sg-tab-count">${count}</span>` : ""}
        ${statusPill(st)}
      </label>`;
    })
    .join("");

  const tabPanels  = TOOL_ORDER
    .map(t => `<div class="sg-tab-panel" data-tool="${t}">${panelBody(t)}</div>`)
    .join("");

  const reasoningCards = (rep.intelligence.reasoning || [])
    .map(r => `
      <div class="sg-card">
        <h3 class="sg-card-title sg-mono">${e(r.issue)}</h3>
        <p class="sg-card-body">${e(r.why)}</p>
      </div>`)
    .join("");

  const recList = (rep.intelligence.recommendations || [])
    .map(r => `<li>${e(r)}</li>`)
    .join("");

  const remedItems = (rep.remediation.plan || [])
    .map(p => `
      <li>
        <span class="sg-mono">${e(p.issue)}</span> — ${e(p.patch?.action || "manual")}
        ${p.patch?.cmd ? `<code class="sg-cmd">${e(p.patch.cmd)}</code>` : ""}
      </li>`)
    .join("");

  const surfaceChips  = surfaces.map(s => `<span class="sg-chip">${e(s)}</span>`).join("");

  const score    = rep.securityScore ?? 100;
  const band     = bandFromScore(score);
  const bandLbl  = band.toUpperCase();
  const passText = rep.status === "PASS" ? "PASS" : "FAIL";
  const passCls  = rep.status === "PASS" ? "sg-pass-ok" : "sg-pass-fail";

  let baselineDiffHtml = "";
  if (rep.baselineDiff) {
    const bd = rep.baselineDiff;
    baselineDiffHtml = `
    <section id="baseline">
      <div class="sg-section-head"><h2 class="sg-section-title">Baseline diff</h2></div>
      <div class="sg-kpi-row sg-kpi-3">
        <div class="sg-kpi"><div class="sg-kpi-label">Net-new</div><div class="sg-kpi-value">${e(bd.netNew)}</div></div>
        <div class="sg-kpi"><div class="sg-kpi-label">Baseline matched</div><div class="sg-kpi-value">${e(bd.baselineMatchedCount)}</div></div>
        <div class="sg-kpi"><div class="sg-kpi-label">Suppressed</div><div class="sg-kpi-value">${e(rep.suppressions?.count ?? 0)}</div></div>
      </div>
    </section>`;
  }

  const sections = [
    { id: "summary",      label: "Summary",       count: null },
    { id: "surface",      label: "Attack surface", count: surfaces.length || null },
    ...(rep.baselineDiff ? [{ id: "baseline", label: "Baseline diff", count: null }] : []),
    { id: "findings",     label: "Findings",      count: rep.findings.length },
    { id: "reasoning",    label: "Reasoning",     count: (rep.intelligence.reasoning || []).length || null },
    { id: "recommendations", label: "Recommendations", count: (rep.intelligence.recommendations || []).length || null },
    { id: "remediation",  label: "Remediation",   count: (rep.remediation.plan || []).length || null },
    { id: "tools",        label: "Tools",         count: TOOL_ORDER.length }
  ];

  const navHtml = sections
    .map((s, i) =>
      `<a href="#${s.id}" data-target="${s.id}" class="sg-nav-link${i === 0 ? " active" : ""}">${e(s.label)}${s.count != null ? `<span class="sg-nav-count">${e(s.count)}</span>` : ""}</a>`
    )
    .join("");

  const toolsTableRows = TOOL_ORDER
    .map(t => {
      const st = tools[t] || "pending";
      const ct = byTool[t].length;
      return `<tr><td>${e(TOOL_LABEL[t])}</td><td>${statusPill(st)}</td><td class="sg-num">${e(ct)}</td></tr>`;
    })
    .join("");

  return `<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecGate Report — ${e(repoName)}</title>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{
    --color-pink:#e8155f;--color-green:#00976a;--color-amber:#b45309;--color-red:#c5173a;
    --color-muted:#7c5e9e;--color-bg:#fef8ff;--color-surface:#f4ecff;--color-border:#e2cefd;
    --color-text:#1a0a2e;--color-text-secondary:#3d1f5a;
    --band-strong-bg:#dcfce7;--band-strong-fg:#166534;
    --band-good-bg:#dbeafe;--band-good-fg:#1d4ed8;
    --band-mixed-bg:#fef3c7;--band-mixed-fg:#92400e;
    --band-weak-bg:#fee2e2;--band-weak-fg:#991b1b;
    --radius:6px;
    --font:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    --font-mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  }
  [data-theme="dark"]{
    --color-pink:#ff2d78;--color-green:#00d68f;--color-amber:#ffaa00;--color-red:#ff4d6a;
    --color-muted:#8b7aa8;--color-bg:#0a0a0f;--color-surface:#13131f;--color-border:#2a1f3d;
    --color-text:#f0e6ff;--color-text-secondary:#c4b5e8;
    --band-strong-bg:#0a2e1e;--band-strong-fg:#00d68f;
    --band-good-bg:#1a0f35;--band-good-fg:#c4b5e8;
    --band-mixed-bg:#2e1f0a;--band-mixed-fg:#ffaa00;
    --band-weak-bg:#2e0a18;--band-weak-fg:#ff8aad;
  }
  html,body{margin:0}
  body{font-family:var(--font);background:var(--color-bg);color:var(--color-text);font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
  a{color:inherit;text-decoration:none}
  a:hover{opacity:.85}

  .sg-shell{display:grid;grid-template-columns:240px minmax(0,1fr);min-height:100vh}
  .sg-aside{position:sticky;top:0;align-self:start;height:100vh;border-right:1px solid var(--color-border);background:var(--color-surface);padding:1.25rem 0;overflow-y:auto;z-index:10;display:flex;flex-direction:column}
  .sg-brand{padding:0 1.25rem 1rem;border-bottom:1px solid var(--color-border);margin-bottom:1rem}
  .sg-brand-kicker{font-size:.7rem;text-transform:uppercase;letter-spacing:.14em;color:var(--color-pink);font-weight:700}
  .sg-brand-name{font-size:.95rem;font-weight:600;margin-top:.5rem;word-break:break-all}
  .sg-brand-target{font-family:var(--font-mono);font-size:.72rem;color:var(--color-muted);margin-top:.2rem;word-break:break-all}
  .sg-brand-score{display:flex;align-items:baseline;gap:.4rem;margin-top:.85rem}
  .sg-brand-score .sg-num{font-size:1.7rem;font-weight:700;letter-spacing:-.02em;font-variant-numeric:tabular-nums;line-height:1}
  .sg-brand-score .sg-denom{font-size:.7rem;color:var(--color-muted)}
  .sg-band{display:inline-block;font-size:.6rem;font-weight:700;letter-spacing:.1em;padding:.15rem .55rem;border-radius:999px;margin-top:.4rem;text-transform:uppercase}
  .sg-band-strong{background:var(--band-strong-bg);color:var(--band-strong-fg)}
  .sg-band-good{background:var(--band-good-bg);color:var(--band-good-fg)}
  .sg-band-mixed{background:var(--band-mixed-bg);color:var(--band-mixed-fg)}
  .sg-band-weak{background:var(--band-weak-bg);color:var(--band-weak-fg)}
  .sg-pass{display:inline-block;font-size:.6rem;font-weight:700;letter-spacing:.1em;padding:.15rem .55rem;border-radius:999px;margin-top:.4rem;margin-left:.35rem;text-transform:uppercase}
  .sg-pass-ok{background:var(--band-strong-bg);color:var(--band-strong-fg)}
  .sg-pass-fail{background:var(--band-weak-bg);color:var(--band-weak-fg)}
  .sg-brand-meta{font-size:.7rem;color:var(--color-muted);margin-top:.55rem;font-family:var(--font-mono);line-height:1.5;word-break:break-all}

  .sg-nav-section{font-size:.65rem;text-transform:uppercase;letter-spacing:.14em;color:var(--color-muted);font-weight:700;padding:.75rem 1.25rem .35rem}
  .sg-nav{flex:1;display:flex;flex-direction:column}
  .sg-nav-link{display:flex;align-items:center;justify-content:space-between;padding:.55rem 1.25rem;font-size:.88rem;font-weight:500;letter-spacing:.02em;color:var(--color-text-secondary);border-left:3px solid transparent;transition:background .12s,color .12s,border-color .12s}
  .sg-nav-link:hover{background:var(--color-bg);color:var(--color-text);opacity:1}
  .sg-nav-link.active{background:var(--color-bg);color:var(--color-pink);border-left-color:var(--color-pink);font-weight:700}
  .sg-nav-count{font-size:.7rem;font-weight:700;color:var(--color-muted);background:var(--color-surface);border:1px solid var(--color-border);border-radius:10px;padding:.05em .45em;font-variant-numeric:tabular-nums}
  .sg-nav-link.active .sg-nav-count{color:var(--color-pink);border-color:var(--color-pink)}

  .sg-export-row{padding:1rem 1.25rem;border-top:1px solid var(--color-border);margin-top:.75rem;display:flex;flex-direction:column;gap:.4rem}
  #sg-theme-toggle{display:inline-flex;align-items:center;justify-content:center;gap:.4rem;padding:.5rem .75rem;border:1px solid var(--color-border);border-radius:var(--radius);font-size:.78rem;color:var(--color-text);background:transparent;cursor:pointer;font-family:inherit;font-weight:500;width:100%;transition:border-color .12s,color .12s}
  #sg-theme-toggle:hover{border-color:var(--color-pink);color:var(--color-pink)}

  .sg-main{padding:1.5rem 2rem 2rem;max-width:none}
  .sg-main section{padding:1.25rem 0;border-bottom:1px solid var(--color-border);scroll-margin-top:1rem}
  .sg-main section:last-of-type{border-bottom:none}
  .sg-section-head{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:1rem}
  .sg-section-title{font-size:1.2rem;font-weight:700;margin:0;letter-spacing:-.01em}
  .sg-section-meta{font-size:.72rem;color:var(--color-muted)}

  .sg-lede{font-size:1rem;line-height:1.45;font-weight:500;margin:0 0 .5rem}
  .sg-lede em{color:var(--color-pink);font-style:normal;font-weight:700}
  .sg-lede-sub{font-size:.85rem;color:var(--color-text-secondary);margin:0}

  .sg-kpi-row{display:grid;grid-template-columns:repeat(8,1fr);gap:.65rem;margin-top:1rem}
  .sg-kpi-row.sg-kpi-3{grid-template-columns:repeat(3,1fr)}
  .sg-kpi{background:var(--color-surface);border:1px solid var(--color-border);border-radius:calc(var(--radius)*1.5);padding:.75rem .85rem}
  .sg-kpi-label{font-size:.68rem;color:var(--color-muted);letter-spacing:.04em;text-transform:uppercase;font-weight:600}
  .sg-kpi-value{font-size:1.5rem;font-weight:700;margin-top:.25rem;letter-spacing:-.02em;font-variant-numeric:tabular-nums;line-height:1.1}
  .sg-kpi-value.sg-fg-critical{color:var(--color-red)}
  .sg-kpi-value.sg-fg-high{color:var(--color-amber)}
  .sg-kpi-value.sg-fg-medium{color:var(--color-amber)}
  .sg-kpi-value.sg-fg-low{color:var(--color-green)}
  .sg-kpi-value.sg-fg-unknown{color:var(--color-muted)}

  .sg-card{background:var(--color-surface);border:1px solid var(--color-border);border-radius:calc(var(--radius)*1.5);padding:1rem}
  .sg-card+.sg-card{margin-top:.75rem}
  .sg-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:.75rem}
  .sg-card-title{font-size:.85rem;font-weight:600;margin:0 0 .35rem;color:var(--color-text)}
  .sg-card-body{font-size:.85rem;color:var(--color-text-secondary);margin:0;line-height:1.5}

  .sg-chip{display:inline-block;padding:.2rem .55rem;margin:.15rem .25rem .15rem 0;border-radius:999px;background:var(--color-surface);border:1px solid var(--color-border);font-size:.75rem;color:var(--color-text-secondary)}

  .sg-pill{display:inline-block;font-size:.65rem;font-weight:700;padding:.15rem .55rem;border-radius:999px;border:1px solid var(--color-border);color:var(--color-text-secondary);background:var(--color-surface);text-transform:uppercase;letter-spacing:.04em}
  .sg-pill-ok{color:var(--band-strong-fg);border-color:var(--band-strong-fg);background:var(--band-strong-bg)}
  .sg-pill-warn{color:var(--band-mixed-fg);border-color:var(--band-mixed-fg);background:var(--band-mixed-bg)}
  .sg-pill-risk{color:var(--band-weak-fg);border-color:var(--band-weak-fg);background:var(--band-weak-bg)}

  .sg-table{width:100%;border-collapse:collapse;margin-top:.5rem}
  .sg-table th,.sg-table td{padding:.55rem .55rem;text-align:left;border-bottom:1px solid var(--color-border);vertical-align:top;font-size:.82rem}
  .sg-table th{font-size:.65rem;font-weight:600;letter-spacing:.06em;color:var(--color-muted);text-transform:uppercase}
  .sg-table td.sg-num,.sg-table th.sg-num{text-align:right;font-variant-numeric:tabular-nums}
  .sg-mono{font-family:var(--font-mono);font-size:.78rem;color:var(--color-muted);word-break:break-all}
  .sg-baseline-row{opacity:.55}
  .sg-bl-badge{display:inline-block;padding:.1rem .45rem;border-radius:3px;background:var(--color-surface);border:1px solid var(--color-border);color:var(--color-muted);font-size:.6rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em}
  .sg-cmd{display:inline-block;padding:.1rem .45rem;margin-left:.4rem;background:var(--color-surface);border:1px solid var(--color-border);border-radius:4px;font-family:var(--font-mono);font-size:.75rem}

  .sg-empty{color:var(--color-muted);font-style:italic;padding:.6rem 0;font-size:.85rem}
  .sg-success{color:var(--color-green);font-style:normal}
  .loc{color:var(--color-pink);text-decoration:none;font-family:var(--font-mono);font-size:.78rem}
  .loc:hover{text-decoration:underline}

  .sg-tabs{margin-top:.5rem}
  .sg-tab-radio{position:absolute;opacity:0;pointer-events:none}
  .sg-tab-bar{display:flex;flex-wrap:wrap;gap:.25rem;border-bottom:1px solid var(--color-border);margin-bottom:1rem}
  .sg-tab-label{display:inline-flex;align-items:center;gap:.5rem;padding:.6rem 1rem;cursor:pointer;color:var(--color-muted);border-bottom:2px solid transparent;margin-bottom:-1px;font-size:.85rem;font-weight:600;transition:color .12s,border-color .12s}
  .sg-tab-label:hover{color:var(--color-text)}
  .sg-tab-count{display:inline-block;min-width:1.2rem;padding:.05em .45em;background:var(--color-surface);border:1px solid var(--color-border);border-radius:10px;font-size:.65rem;font-weight:700;color:var(--color-muted);text-align:center;font-variant-numeric:tabular-nums}
  .sg-tab-panels .sg-tab-panel{display:none}
  #tab-semgrep:checked  ~ .sg-tab-bar label[for="tab-semgrep"],
  #tab-gitleaks:checked ~ .sg-tab-bar label[for="tab-gitleaks"],
  #tab-npm:checked      ~ .sg-tab-bar label[for="tab-npm"],
  #tab-osv:checked      ~ .sg-tab-bar label[for="tab-osv"],
  #tab-trivy:checked    ~ .sg-tab-bar label[for="tab-trivy"]{
    color:var(--color-pink);border-bottom-color:var(--color-pink)
  }
  #tab-semgrep:checked  ~ .sg-tab-bar label[for="tab-semgrep"] .sg-tab-count,
  #tab-gitleaks:checked ~ .sg-tab-bar label[for="tab-gitleaks"] .sg-tab-count,
  #tab-npm:checked      ~ .sg-tab-bar label[for="tab-npm"] .sg-tab-count,
  #tab-osv:checked      ~ .sg-tab-bar label[for="tab-osv"] .sg-tab-count,
  #tab-trivy:checked    ~ .sg-tab-bar label[for="tab-trivy"] .sg-tab-count{
    color:var(--color-pink);border-color:var(--color-pink)
  }
  #tab-semgrep:checked  ~ .sg-tab-panels .sg-tab-panel[data-tool="semgrep"],
  #tab-gitleaks:checked ~ .sg-tab-panels .sg-tab-panel[data-tool="gitleaks"],
  #tab-npm:checked      ~ .sg-tab-panels .sg-tab-panel[data-tool="npm"],
  #tab-osv:checked      ~ .sg-tab-panels .sg-tab-panel[data-tool="osv"],
  #tab-trivy:checked    ~ .sg-tab-panels .sg-tab-panel[data-tool="trivy"]{display:block}

  .sg-list{padding-left:1.1rem;color:var(--color-text-secondary);font-size:.88rem}
  .sg-list li+li{margin-top:.35rem}

  .sg-footer-note{margin-top:1.5rem;padding-top:.75rem;border-top:1px solid var(--color-border);font-size:.7rem;color:var(--color-muted);font-family:var(--font-mono);text-align:center}

  @media(max-width:900px){
    .sg-shell{grid-template-columns:1fr}
    .sg-aside{position:static;height:auto;border-right:none;border-bottom:1px solid var(--color-border)}
    .sg-main{padding:1.25rem}
    .sg-kpi-row{grid-template-columns:repeat(2,1fr)}
  }
  @media print{
    .sg-aside{display:none}
    .sg-shell{display:block}
    .sg-main{padding:0}
  }
</style>
<script>
(function(){var s=localStorage.getItem('sg-theme');var d=window.matchMedia('(prefers-color-scheme:dark)').matches;document.documentElement.setAttribute('data-theme',s||(d?'dark':'light'));})();
</script>
</head>
<body>
<div class="sg-shell">
  <aside class="sg-aside">
    <div class="sg-brand">
      <div class="sg-brand-kicker">SecGate</div>
      <div class="sg-brand-name">${e(repoName)}</div>
      <div class="sg-brand-target">${e(rep.target)}</div>
      <div class="sg-brand-score"><span class="sg-num">${e(score)}</span><span class="sg-denom">/100</span></div>
      <div>
        <span class="sg-band sg-band-${band}">${e(bandLbl)}</span>
        <span class="sg-pass ${passCls}">${e(passText)}</span>
      </div>
      <div class="sg-brand-meta">scanned ${e(rep.timestamp)}<br>mode ${e(rep.mode)}</div>
    </div>

    <div class="sg-nav-section">Report</div>
    <nav class="sg-nav" aria-label="Report sections">${navHtml}</nav>

    <div class="sg-export-row">
      <button id="sg-theme-toggle" type="button" aria-label="Toggle theme">🌙 Theme</button>
    </div>
  </aside>

  <main class="sg-main">
    <section id="summary">
      <div class="sg-section-head">
        <h2 class="sg-section-title">Summary</h2>
        <div class="sg-section-meta">SecGate v${e(rep.version)}</div>
      </div>
      <p class="sg-lede">Posture is <em>${e(band)}</em>. ${sum.critical + sum.high > 0 ? `${e(sum.critical)} critical, ${e(sum.high)} high-severity finding(s) require attention.` : `No critical or high-severity findings.`}</p>
      <p class="sg-lede-sub">Risk score ${e(rep.intelligence.riskScore)} · confidence ${e(rep.remediation.confidence)}% · ${e(rep.findings.length)} total finding(s) across ${TOOL_ORDER.length} tools.</p>
      <div class="sg-kpi-row">
        <div class="sg-kpi"><div class="sg-kpi-label">Score</div><div class="sg-kpi-value">${e(score)}<span style="font-size:.6em;color:var(--color-muted)">/100</span></div></div>
        <div class="sg-kpi"><div class="sg-kpi-label">Risk</div><div class="sg-kpi-value">${e(rep.intelligence.riskScore)}</div></div>
        <div class="sg-kpi"><div class="sg-kpi-label">Confidence</div><div class="sg-kpi-value">${e(rep.remediation.confidence)}%</div></div>
        <div class="sg-kpi"><div class="sg-kpi-label">Critical</div><div class="sg-kpi-value sg-fg-critical">${e(sum.critical)}</div></div>
        <div class="sg-kpi"><div class="sg-kpi-label">High</div><div class="sg-kpi-value sg-fg-high">${e(sum.high)}</div></div>
        <div class="sg-kpi"><div class="sg-kpi-label">Medium</div><div class="sg-kpi-value sg-fg-medium">${e(sum.medium)}</div></div>
        <div class="sg-kpi"><div class="sg-kpi-label">Low</div><div class="sg-kpi-value sg-fg-low">${e(sum.low)}</div></div>
        <div class="sg-kpi"><div class="sg-kpi-label">Unknown</div><div class="sg-kpi-value sg-fg-unknown">${e(sum.unknown || 0)}</div></div>
      </div>
    </section>

    <section id="surface">
      <div class="sg-section-head"><h2 class="sg-section-title">Attack surface</h2></div>
      <div>${surfaceChips || '<span class="sg-empty">Nothing detected.</span>'}</div>
    </section>

    ${baselineDiffHtml}

    <section id="findings">
      <div class="sg-section-head">
        <h2 class="sg-section-title">Findings</h2>
        <div class="sg-section-meta">${e(rep.findings.length)} total</div>
      </div>
      <div class="sg-tabs">
        ${tabInputs}
        <div class="sg-tab-bar">${tabLabels}</div>
        <div class="sg-tab-panels">${tabPanels}</div>
      </div>
    </section>

    <section id="reasoning">
      <div class="sg-section-head"><h2 class="sg-section-title">Reasoning</h2></div>
      ${reasoningCards ? `<div class="sg-cards">${reasoningCards}</div>` : '<div class="sg-empty">No reasoning produced.</div>'}
    </section>

    <section id="recommendations">
      <div class="sg-section-head"><h2 class="sg-section-title">Recommendations</h2></div>
      ${recList ? `<ul class="sg-list">${recList}</ul>` : '<div class="sg-empty">No recommendations.</div>'}
    </section>

    <section id="remediation">
      <div class="sg-section-head"><h2 class="sg-section-title">Remediation plan</h2></div>
      ${remedItems ? `<ul class="sg-list">${remedItems}</ul>` : '<div class="sg-empty">No plan items.</div>'}
    </section>

    <section id="tools">
      <div class="sg-section-head"><h2 class="sg-section-title">Tools</h2></div>
      <table class="sg-table">
        <thead><tr><th>Tool</th><th>Status</th><th class="sg-num">Findings</th></tr></thead>
        <tbody>${toolsTableRows}</tbody>
      </table>
    </section>

    <div class="sg-footer-note">SecGate v${e(rep.version)} · MIT · TinyDarkForge</div>
  </main>
</div>

<script>
(function(){
  var btn=document.getElementById('sg-theme-toggle');
  function sync(){var d=document.documentElement.getAttribute('data-theme')==='dark';btn.textContent=d?'☀ Theme':'🌙 Theme';btn.setAttribute('aria-label',d?'Switch to light theme':'Switch to dark theme');}
  if(btn){sync();btn.addEventListener('click',function(){var d=document.documentElement.getAttribute('data-theme')==='dark';var n=d?'light':'dark';document.documentElement.setAttribute('data-theme',n);try{localStorage.setItem('sg-theme',n);}catch(_){}sync();});}
  var links=document.querySelectorAll('.sg-nav-link[data-target]');var byId={};var sections=[];
  links.forEach(function(l){var id=l.getAttribute('data-target');var el=document.getElementById(id);byId[id]=l;if(el)sections.push(el);});
  if('IntersectionObserver' in window){
    var io=new IntersectionObserver(function(es){es.forEach(function(en){if(en.isIntersecting){links.forEach(function(l){l.classList.remove('active');});var lk=byId[en.target.id];if(lk)lk.classList.add('active');}});},{rootMargin:'-20% 0% -70% 0%',threshold:0});
    sections.forEach(function(s){io.observe(s);});
  }
})();
</script>
</body>
</html>`;
}

/* ────────────────────────────────────────────────────────────────────────────
   SARIF 2.1.0 serializer
   ──────────────────────────────────────────────────────────────────────────── */

const SARIF_LEVEL = {
  CRITICAL: "error",
  HIGH:     "error",
  MEDIUM:   "warning",
  LOW:      "note",
  UNKNOWN:  "none"
};

const SARIF_SCORE = {
  CRITICAL: 9.5,
  HIGH:     7.5,
  MEDIUM:   5.0,
  LOW:      2.0,
  UNKNOWN:  0.0
};

const TOOL_INFO = {
  semgrep:    { name: "Semgrep",     uri: "https://semgrep.dev" },
  gitleaks:   { name: "Gitleaks",    uri: "https://github.com/gitleaks/gitleaks" },
  npm:        { name: "npm audit",   uri: "https://docs.npmjs.com/cli/commands/npm-audit" },
  osv:        { name: "osv-scanner", uri: "https://github.com/google/osv-scanner" },
  trivy:      { name: "Trivy",       uri: "https://github.com/aquasecurity/trivy" },
  trivyImage: { name: "Trivy Image", uri: "https://github.com/aquasecurity/trivy" }
};

function toolVersion(binary) {
  try {
    const out = execFileSync(binary, ["--version"], {
      encoding: "utf-8",
      stdio: "pipe",
      timeout: 5000
    });
    const m = out.match(/(\d+\.\d+\.\d+[\w.-]*)/);
    return m ? m[1] : "unknown";
  } catch {
    return "unknown";
  }
}

function relativizeUri(filePath, baseDir) {
  if (!filePath) return null;
  if (path.isAbsolute(filePath)) {
    const rel = path.relative(baseDir, filePath);
    return rel.startsWith("..") ? filePath : rel;
  }
  return filePath;
}

export function buildSarif(rep, repoName, baseDir) {
  const toolGroups = {};
  for (const f of rep.findings) {
    if (!toolGroups[f.tool]) toolGroups[f.tool] = [];
    toolGroups[f.tool].push(f);
  }

  const runs = TOOLS.map(toolKey => {
    const info        = TOOL_INFO[toolKey] || { name: toolKey, uri: "" };
    const toolFindings = toolGroups[toolKey] || [];

    const rules   = [];
    const ruleIds = new Set();
    for (const f of toolFindings) {
      if (!ruleIds.has(f.signature)) {
        ruleIds.add(f.signature);
        rules.push({
          id:               f.signature,
          name:             f.signature,
          shortDescription: { text: f.message || f.signature },
          properties:       { "security-severity": String(SARIF_SCORE[f.severity] ?? 0) }
        });
      }
    }

    const results = toolFindings.map(f => {
      const uri    = relativizeUri(f.file, baseDir);
      const region = {};
      if (f.line    != null) region.startLine   = f.line;
      if (f.col     != null) region.startColumn = f.col;
      if (f.endLine != null) region.endLine     = f.endLine;

      const location = uri
        ? {
            physicalLocation: {
              artifactLocation: { uri, uriBaseId: "%SRCROOT%" },
              ...(Object.keys(region).length ? { region } : {})
            }
          }
        : null;

      return {
        ruleId:  f.signature,
        level:   SARIF_LEVEL[f.severity] || "none",
        message: { text: f.message || f.signature },
        ...(location ? { locations: [location] } : {}),
        properties: {
          "security-severity": String(SARIF_SCORE[f.severity] ?? 0),
          tool:       f.tool,
          type:       f.type,
          fixableBy:  f.fixableBy || null
        }
      };
    });

    const binary  = toolKey === "osv" ? "osv-scanner" : toolKey === "npm" ? null : toolKey === "trivyImage" ? "trivy" : toolKey;
    const status  = rep.tools[toolKey] || "pending";
    const version = (binary && status !== "skipped" && status !== "pending")
      ? toolVersion(binary)
      : "unknown";

    return {
      tool: {
        driver: {
          name:           info.name,
          version,
          informationUri: info.uri,
          rules
        }
      },
      results,
      artifacts:  [],
      properties: { toolStatus: rep.tools[toolKey] || "pending" }
    };
  });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
    version: "2.1.0",
    runs
  };
}
