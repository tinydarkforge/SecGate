/**
 * Confidence classification for SecGate findings.
 *
 * Two profiles:
 *   - "curated"  (default) — applies a built-in noisy-rule list, marking
 *                            common false-positive patterns as
 *                            "informational" instead of "actionable".
 *                            Findings are still shown; they are demoted
 *                            so the report's first impression is signal.
 *   - "strict"            — no demotion. Every finding is "actionable".
 *
 * Suppressed findings (inline `# secgate:ignore`, baseline matches) are
 * handled elsewhere (lib/scanners.mjs and lib/baseline.mjs); they never
 * reach this classifier.
 */

const STALE_CVE_YEARS = 5;

/** Regex patterns that are demoted to "informational" under curated profile. */
const INFORMATIONAL_RULE_PATTERNS = [
  // HTML SRI hint — fires on every script tag without integrity attribute,
  // including inline favicons + data-URI scripts. Real CDN MITM risk is
  // covered by other layers (HSTS, COEP) on most modern stacks.
  /^html\.security\.audit\.missing-integrity/i,

  // Common Semgrep FP in CLI tools that legitimately resolve user-supplied
  // paths against a known root. SecGate's own codebase suppresses this rule
  // explicitly; the broader ecosystem hits it in any path-resolving CLI.
  /^javascript\.lang\.security\.audit\.path-traversal\.path-join-resolve-traversal/i,
];

/**
 * Classify a finding's confidence under the active profile.
 * @param {object} finding — { tool, severity, signature, image, ... }
 * @param {string} profile — "curated" | "strict"
 * @returns {"actionable" | "informational"}
 */
export function getConfidence(finding, profile) {
  if (profile === "strict") return "actionable";

  // UNKNOWN severity = scanner couldn't classify → informational.
  if (String(finding.severity).toUpperCase() === "UNKNOWN") return "informational";

  // Trivy base-image OS package CVEs at LOW/MEDIUM are rarely reachable
  // from a Node/Python/Go app runtime (apt, libtinfo, perl-base, etc.).
  // Mark these informational; CRITICAL/HIGH still actionable.
  if (finding.tool === "trivyImage") {
    const sev = String(finding.severity).toUpperCase();
    if (sev === "LOW" || sev === "MEDIUM") return "informational";
  }

  // Stale CVE detection: signature embeds CVE-YYYY-NNNNN. If YYYY is older
  // than (currentYear - STALE_CVE_YEARS) AND severity is not CRITICAL,
  // demote. Old + unfixed in a maintained image usually means upstream
  // decided exploitability is bounded.
  const cveMatch = String(finding.signature || "").match(/CVE-(\d{4})-\d+/i);
  if (cveMatch) {
    const year = parseInt(cveMatch[1], 10);
    const currentYear = new Date().getFullYear();
    if (year < currentYear - STALE_CVE_YEARS) {
      const sev = String(finding.severity).toUpperCase();
      if (sev !== "CRITICAL") return "informational";
    }
  }

  // Pattern-list match.
  for (const pat of INFORMATIONAL_RULE_PATTERNS) {
    if (pat.test(finding.signature || "")) return "informational";
  }

  return "actionable";
}

/**
 * Bucket a list of findings by confidence under the active profile.
 * @returns {{ actionable: object[], informational: object[] }}
 */
export function bucketByConfidence(findings, profile) {
  const actionable = [];
  const informational = [];
  for (const f of findings) {
    if (getConfidence(f, profile) === "informational") informational.push(f);
    else actionable.push(f);
  }
  return { actionable, informational };
}

/**
 * Human-readable explanation of why a curated profile demoted a finding.
 * Returned as a short tag for display (e.g. "stale CVE", "base-image LOW").
 */
export function informationalReason(finding) {
  const sev = String(finding.severity).toUpperCase();

  if (sev === "UNKNOWN") return "unknown severity";

  if (finding.tool === "trivyImage" && (sev === "LOW" || sev === "MEDIUM")) {
    return "base-image OS package";
  }

  const cveMatch = String(finding.signature || "").match(/CVE-(\d{4})-\d+/i);
  if (cveMatch) {
    const year = parseInt(cveMatch[1], 10);
    const currentYear = new Date().getFullYear();
    if (year < currentYear - STALE_CVE_YEARS && sev !== "CRITICAL") {
      return `${currentYear - year}yr-old CVE`;
    }
  }

  for (const pat of INFORMATIONAL_RULE_PATTERNS) {
    if (pat.test(finding.signature || "")) return "noisy rule";
  }

  return "informational";
}
