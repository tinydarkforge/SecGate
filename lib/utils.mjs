import { execFileSync } from "child_process";

export function runTool(binary, args, opts = {}) {
  try {
    return execFileSync(binary, args, {
      encoding: "utf-8",
      stdio: "pipe",
      maxBuffer: 64 * 1024 * 1024,
      ...opts
    });
  } catch (e) {
    return (e.stdout || "").toString();
  }
}

export function toolExists(cmd) {
  try {
    execFileSync("which", [cmd], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const SEVERITY_TIERS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

export function normalizeSeverity(raw) {
  if (raw == null) return "UNKNOWN";
  const v = String(raw).trim().toUpperCase();
  if (v === "MODERATE") return "MEDIUM";
  if (v === "WARNING") return "MEDIUM";
  if (v === "ERROR") return "HIGH";
  if (v === "INFO" || v === "NOTE" || v === "INFORMATIONAL") return "LOW";
  if (v === "NEGLIGIBLE") return "LOW";
  return SEVERITY_TIERS.includes(v) ? v : "UNKNOWN";
}

export function matchPattern(pattern, value) {
  if (!pattern.includes("*")) return pattern === value;
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`).test(value);
}

export function matchesAny(patterns, value) {
  return patterns.some(p => matchPattern(p, value));
}
