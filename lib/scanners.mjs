import fs from "fs";
import path from "path";
import { runTool, toolExists, normalizeSeverity, matchPattern, matchesAny } from "./utils.mjs";

const SEMGREP_TIER = {
  ERROR: "HIGH",
  WARNING: "MEDIUM",
  INFO: "LOW",
  NOTE: "LOW"
};

const SECRET_RE = /(secret|credential|password|token|api[_-]?key|hardcoded)/i;
const SECRET_CWES = ["CWE-798", "CWE-259", "CWE-321", "CWE-522"];

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

function severityFromCvss(score) {
  if (!Number.isFinite(score) || score <= 0) return null;
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  return "LOW";
}

function cvssBaseScore(vec) {
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

  const dbSev = v.database_specific?.severity;
  const byDb = ratingFromText(dbSev);
  if (byDb) return byDb;

  for (const s of sev) {
    const byText = ratingFromText(s.type) || ratingFromText(s.score);
    if (byText) return byText;
  }

  const byDetails = ratingFromText(v.details);
  if (byDetails) return byDetails;

  return "UNKNOWN";
}

const SKIP_DIRS = new Set(["node_modules", ".git"]);
const DOCKERFILE_GLOB_RE = /^(Dockerfile|.+\.Dockerfile)$/;

function findDockerfiles(dir) {
  const results = [];
  function walk(d) {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name) && !e.name.startsWith(".git")) {
          walk(path.join(d, e.name));
        }
      } else if (e.isFile() && DOCKERFILE_GLOB_RE.test(e.name)) {
        results.push(path.join(d, e.name));
      }
    }
  }
  walk(dir);
  return results;
}

function extractBaseImages(dockerfilePath) {
  let content;
  try { content = fs.readFileSync(dockerfilePath, "utf-8"); } catch { return []; }
  const images = new Set();
  for (const line of content.split("\n")) {
    const m = line.match(/^FROM\s+(?:--platform=\S+\s+)?([^\s]+)(?:\s+AS\s+\S+)?$/i);
    if (m) {
      const ref = m[1];
      if (ref.toLowerCase() !== "scratch") images.add(ref);
    }
  }
  return [...images];
}

/**
 * Check a source file for an inline suppression comment on line N or N-1.
 */
export function hasInlineSuppression(filePath, lineNumber, ruleId) {
  if (!filePath || lineNumber == null) return false;

  let src;
  try {
    src = fs.readFileSync(filePath, "utf-8");
  } catch {
    return false;
  }

  const lines = src.split("\n");
  const checkLines = [lineNumber - 1, lineNumber - 2].filter(i => i >= 0);

  for (const idx of checkLines) {
    const line = lines[idx] || "";
    const suppressRe = /(?:#|\/\/|\/\*)\s*secgate:ignore\s+(\S+)/;
    const m = line.match(suppressRe);
    if (m) {
      const suppressedRule = m[1];
      if (matchPattern(suppressedRule, ruleId)) {
        return suppressedRule;
      }
    }
  }
  return false;
}

/**
 * Build a finding-processor bound to the given config, target, suppressions state.
 * Returns an addFinding function for scanners to call.
 */
export function makeFindingProcessor(config, target, findings, suppressions) {
  return function addFinding(f) {
    const rawSeverity = normalizeSeverity(f.severity);
    const signature = f.signature || "";

    const severity = applyOverrides(config, rawSeverity, signature);

    if (matchesAny(config.ignore, signature)) return;

    const resolvedFile = f.file
      ? (path.isAbsolute(f.file) ? f.file : path.join(target, f.file))
      : null;
    const suppressedRule = hasInlineSuppression(resolvedFile, f.line, signature);
    if (suppressedRule) {
      suppressions.count++;
      suppressions.byRule[suppressedRule] = (suppressions.byRule[suppressedRule] || 0) + 1;
      return;
    }

    const fixableBy =
      f.fixableBy === "auto" || f.fixableBy === "manual"
        ? f.fixableBy
        : f.fixable
        ? "manual"
        : null;

    const finding = {
      tool: f.tool,
      type: f.type,
      severity,
      signature,
      message: f.message,
      file: f.file ?? null,
      line: f.line ?? null,
      col: f.col ?? null,
      endLine: f.endLine ?? null,
      fixable: fixableBy === "auto",
      fixableBy
    };

    if (f.scanMode != null) finding.scanMode = f.scanMode;
    if (f.image != null) finding.image = f.image;

    findings.push(finding);
  };
}

function applyOverrides(config, severity, signature) {
  for (const ov of config.severityOverrides) {
    if (ov && typeof ov.rule === "string" && typeof ov.severity === "string") {
      if (matchPattern(ov.rule, signature)) {
        return normalizeSeverity(ov.severity);
      }
    }
  }
  return severity;
}

/**
 * Each scanner returns { status, skipReason? } and calls addFinding for each hit.
 * All are deterministic when the tool binary is missing: status="skipped", skipReason set.
 */

export function runGitleaks(target, config, addFinding, debugFn) {
  if (config.scanners.gitleaks === false) {
    return { status: "skipped", skipReason: "disabled in config" };
  }
  if (!toolExists("gitleaks")) {
    return { status: "skipped", skipReason: "not installed" };
  }

  const out = runTool("gitleaks", ["detect", "--source", target, "--report-format", "json"]);
  if (debugFn) debugFn("gitleaks", out);

  if (!out.trim()) return { status: "clean" };

  try {
    const data = JSON.parse(out);
    const before = [];
    const snapshot = [];

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

    return { status: data.length > 0 ? "ran" : "clean" };
  } catch {
    return { status: "error" };
  }
}

export function runSemgrep(target, config, addFinding, debugFn) {
  if (config.scanners.semgrep === false) {
    return { status: "skipped", skipReason: "disabled in config" };
  }
  if (!toolExists("semgrep")) {
    return { status: "skipped", skipReason: "not installed" };
  }

  const semgrepArgs = ["--config=auto", "--json", target];
  if (config.customSemgrepRules) {
    semgrepArgs.unshift(`--config=${config.customSemgrepRules}`);
  }

  const out = runTool("semgrep", semgrepArgs);
  if (debugFn) debugFn("semgrep", out);

  try {
    const data = JSON.parse(out);
    const added = [];

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

    return { status: data.results.length > 0 ? "ran" : "clean" };
  } catch {
    return { status: "error" };
  }
}

export function runOsvScanner(target, config, addFinding, debugFn) {
  if (config.scanners.osv === false) {
    return { status: "skipped", skipReason: "disabled in config" };
  }
  if (!toolExists("osv-scanner")) {
    return { status: "skipped", skipReason: "not installed" };
  }

  const out = runTool("osv-scanner", ["--format", "json", "-r", target]);
  if (debugFn) debugFn("osv-scanner", out);

  if (!out.trim() || /No package sources found/i.test(out)) {
    return { status: "clean" };
  }

  try {
    const data = JSON.parse(out);
    const results = data.results || [];
    let count = 0;

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
          count++;
        }
      }
    }

    return { status: count > 0 ? "ran" : "clean" };
  } catch {
    return { status: "error" };
  }
}

export function runTrivy(target, config, addFinding, debugFn) {
  if (config.scanners.trivy === false) {
    return { status: "skipped", skipReason: "disabled in config" };
  }
  if (!toolExists("trivy")) {
    return { status: "skipped", skipReason: "not installed" };
  }

  const out = runTool("trivy", [
    "fs",
    "--quiet",
    "--format", "json",
    "--scanners", "misconfig,license",
    ...(process.env.SECGATE_INTERNAL_TEST === "1" ? ["--skip-dirs", "**/test/fixtures"] : []),
    "--skip-dirs", "**/node_modules",
    target
  ]);
  if (debugFn) debugFn("trivy", out);

  try {
    const data = JSON.parse(out);
    const results = data.Results || [];
    let count = 0;

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
        count++;
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
        count++;
      }
    }

    return { status: count > 0 ? "ran" : "clean" };
  } catch {
    return { status: "error" };
  }
}

export function runTrivyImage(target, config, addFinding, debugFn) {
  if (config.scanners.trivy === false) {
    return { status: "skipped", skipReason: "disabled in config" };
  }
  if (!toolExists("trivy")) {
    return { status: "skipped" };
  }

  const isInternalTest = process.env.SECGATE_INTERNAL_TEST === "1";
  const dockerfiles = findDockerfiles(target).filter(f => !isInternalTest || !f.includes("/test/fixtures"));
  if (dockerfiles.length === 0) return { status: "skipped" };

  const imageRefs = new Set();
  for (const df of dockerfiles) {
    for (const ref of extractBaseImages(df)) {
      imageRefs.add(ref);
    }
  }

  if (imageRefs.size === 0) return { status: "skipped" };

  let anyRan = false;
  let anyError = false;
  let count = 0;

  for (const imageRef of imageRefs) {
    const out = runTool("trivy", [
      "image",
      "--format", "json",
      "--quiet",
      imageRef
    ], { timeout: 120000 });
    if (debugFn) debugFn(`trivy image ${imageRef}`, out);

    if (!out.trim()) { anyError = true; continue; }

    try {
      const data = JSON.parse(out);
      const results = data.Results || [];
      anyRan = true;

      for (const r of results) {
        for (const v of r.Vulnerabilities || []) {
          addFinding({
            tool: "trivy",
            type: "dependency",
            severity: v.Severity,
            signature: `trivy-image:${imageRef}:${v.VulnerabilityID}`,
            message: v.Title || v.Description || v.VulnerabilityID,
            file: imageRef,
            line: null,
            fixableBy: "manual",
            scanMode: "image",
            image: imageRef
          });
          count++;
        }
      }
    } catch {
      anyError = true;
    }
  }

  if (anyError) return { status: "error" };
  if (count > 0) return { status: "ran" };
  if (anyRan) return { status: "clean" };
  return { status: "error" };
}

export function runNpmAudit(target, config, addFinding, debugFn) {
  if (config.scanners.npm === false) {
    return { status: "skipped", skipReason: "disabled in config" };
  }
  if (!fs.existsSync(path.join(target, "package.json"))) {
    return { status: "skipped", skipReason: "no package.json in target" };
  }

  const out = runTool("npm", ["audit", "--json"], { cwd: target });
  if (debugFn) debugFn("npm audit", out);

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
        addFinding({
          tool: "secgate",
          type: "policy",
          severity: "MEDIUM",
          signature: "no-lockfile",
          message: "package.json present but no lockfile — supply-chain determinism not guaranteed",
          file: "package.json",
          line: null,
          fixableBy: "manual"
        });
        return { status: "skipped", skipReason: "no package-lock.json (run `npm install` to generate)" };
      }
      return { status: "error" };
    }

    const vulns = json.vulnerabilities || {};
    const lockFile = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock"]
      .find(f => fs.existsSync(path.join(target, f))) || "package.json";
    let count = 0;

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
      count++;
    }

    return { status: count > 0 ? "ran" : "clean" };
  } catch {
    return { status: "error" };
  }
}
