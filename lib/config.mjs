import fs from "fs";
import path from "path";

export const CONFIG_DEFAULTS = {
  failOn: ["critical", "high"],
  scanners: { semgrep: true, gitleaks: true, npm: true, osv: true, trivy: true },
  severityOverrides: [],
  ignore: [],
  excludePaths: [],
  baselineFile: ".secgate-baseline.json",
  customSemgrepRules: null
};

function isWithinTarget(targetDir, relPath) {
  if (!relPath) return true;
  if (path.isAbsolute(relPath)) {
    const resolved = path.resolve(relPath);
    const targetResolved = path.resolve(targetDir);
    return resolved.startsWith(targetResolved + path.sep) || resolved === targetResolved;
  }
  if (relPath.includes("..")) return false;
  return true;
}

export function loadConfig(targetDir) {
  const cfgPath = path.join(targetDir, ".secgate.config.json");
  if (!fs.existsSync(cfgPath)) return { ...CONFIG_DEFAULTS };

  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(cfgPath, "utf-8"));
  } catch {
    console.error(`[secgate] Invalid JSON in ${cfgPath} — using defaults`);
    return { ...CONFIG_DEFAULTS };
  }

  let baselineFile = CONFIG_DEFAULTS.baselineFile;
  if (typeof raw.baselineFile === "string") {
    if (isWithinTarget(targetDir, raw.baselineFile)) {
      baselineFile = raw.baselineFile;
    } else {
      console.warn(`[secgate] baselineFile '${raw.baselineFile}' escapes target directory — using default`);
    }
  }

  let customSemgrepRules = null;
  if (typeof raw.customSemgrepRules === "string") {
    if (isWithinTarget(targetDir, raw.customSemgrepRules)) {
      customSemgrepRules = raw.customSemgrepRules;
    } else {
      console.warn(`[secgate] customSemgrepRules '${raw.customSemgrepRules}' escapes target directory — using default`);
    }
  }

  return {
    failOn: Array.isArray(raw.failOn) ? raw.failOn.map(s => String(s).toLowerCase()) : CONFIG_DEFAULTS.failOn,
    scanners: typeof raw.scanners === "object" && raw.scanners !== null
      ? { ...CONFIG_DEFAULTS.scanners, ...raw.scanners }
      : CONFIG_DEFAULTS.scanners,
    severityOverrides: Array.isArray(raw.severityOverrides) ? raw.severityOverrides : [],
    ignore: Array.isArray(raw.ignore) ? raw.ignore : [],
    excludePaths: Array.isArray(raw.excludePaths) ? raw.excludePaths : [],
    baselineFile,
    customSemgrepRules
  };
}
