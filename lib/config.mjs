import fs from "fs";
import path from "path";

export const CONFIG_DEFAULTS = {
  failOn: ["critical", "high"],
  scanners: { semgrep: true, gitleaks: true, npm: true, osv: true, trivy: true },
  severityOverrides: [],
  ignore: [],
  baselineFile: ".secgate-baseline.json",
  customSemgrepRules: null
};

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

  return {
    failOn: Array.isArray(raw.failOn) ? raw.failOn.map(s => String(s).toLowerCase()) : CONFIG_DEFAULTS.failOn,
    scanners: typeof raw.scanners === "object" && raw.scanners !== null
      ? { ...CONFIG_DEFAULTS.scanners, ...raw.scanners }
      : CONFIG_DEFAULTS.scanners,
    severityOverrides: Array.isArray(raw.severityOverrides) ? raw.severityOverrides : [],
    ignore: Array.isArray(raw.ignore) ? raw.ignore : [],
    baselineFile: typeof raw.baselineFile === "string" ? raw.baselineFile : CONFIG_DEFAULTS.baselineFile,
    customSemgrepRules: typeof raw.customSemgrepRules === "string" ? raw.customSemgrepRules : null
  };
}
