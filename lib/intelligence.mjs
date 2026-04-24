import { runTool } from "./utils.mjs";

export function analyze(findings) {
  let risk = 0;
  const surface = new Set();
  const reasoning = [];
  const recs = [];

  for (const f of findings) {
    if (f.baseline) continue;

    const weight =
      f.severity === "CRITICAL" ? 10
      : f.severity === "HIGH"   ? 6
      : f.severity === "MEDIUM" ? 3
      : f.severity === "LOW"    ? 1
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

    if (f.type === "secret")     recs.push("Rotate credentials immediately");
    if (f.type === "dependency") recs.push("Upgrade affected packages");
    if (f.type === "code")       recs.push("Refactor insecure code");
    if (f.type === "iac")        recs.push("Harden infrastructure configuration");
    if (f.type === "license")    recs.push("Review third-party licenses");
  }

  return {
    riskScore: risk,
    attackSurface: [...surface],
    reasoning,
    recommendations: [...new Set(recs)]
  };
}

export function patch(f) {
  if (f.tool === "npm") {
    return {
      action: "npm audit fix",
      cmd: null,
      exec: {
        binary: "npm",
        args: ["audit", "fix", "--ignore-scripts"],
        cwd: null
      }
    };
  }
  if (f.tool === "semgrep")  return { action: "manual code fix", cmd: null };
  if (f.tool === "gitleaks") return { action: "remove + rotate secret", cmd: null };
  if (f.tool === "osv")      return { action: "upgrade dependency", cmd: null };
  if (f.tool === "trivy") {
    return {
      action: f.type === "license" ? "review license" : "fix misconfiguration",
      cmd: null
    };
  }
  return { action: "manual", cmd: null };
}

/**
 * @param {object[]} findings
 * @param {object}   opts
 * @param {boolean}  opts.apply         - execute fixable remediations
 * @param {string}   opts.target        - absolute path to scan target
 * @param {string}   opts.reportTarget  - display path (may be relativized)
 * @param {Function} opts.auditLog      - (event, detail) => void
 */
export function remediate(findings, opts = {}) {
  const { apply = false, target = null, reportTarget = null, auditLog = () => {} } = opts;
  let confidence = 100;
  const plan = [];
  const staged = [];
  const executed = [];
  const blocked = [];

  for (const f of findings) {
    if (f.baseline) continue;

    const p = patch(f);

    if (f.tool === "npm" && p.exec) {
      p.cmd = `npm audit fix --ignore-scripts (cwd=${reportTarget || target || ""})`;
      if (p.exec) p.exec.cwd = target;
    }

    plan.push({ issue: f.signature, patch: p });

    if (f.severity === "CRITICAL") {
      blocked.push(p);
      confidence -= 30;
      continue;
    }

    if (f.fixable && p.exec) {
      staged.push(p);

      if (apply && p.exec.cwd) {
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
          auditLog("apply_ok", { tool: f.tool, signature: f.signature });
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
