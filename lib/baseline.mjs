import fs from "fs";
import path from "path";

export function loadBaseline(config, target) {
  const baselinePath = path.isAbsolute(config.baselineFile)
    ? config.baselineFile
    : path.join(target, config.baselineFile);

  if (!fs.existsSync(baselinePath)) return null;

  try {
    const raw = JSON.parse(fs.readFileSync(baselinePath, "utf-8"));
    if (!Array.isArray(raw.findings)) {
      console.error(`[secgate] Baseline file ${baselinePath} missing 'findings' array — ignoring`);
      return null;
    }
    return raw;
  } catch {
    console.error(`[secgate] Could not parse baseline file: ${baselinePath}`);
    return null;
  }
}

export function writeBaseline(config, target, findings) {
  const baselinePath = path.isAbsolute(config.baselineFile)
    ? config.baselineFile
    : path.join(target, config.baselineFile);

  const baseline = {
    generatedAt: new Date().toISOString(),
    findings: findings.map(f => ({
      signature: f.signature,
      severity: f.severity,
      file: f.file,
      line: f.line
    }))
  };

  fs.writeFileSync(baselinePath, JSON.stringify(baseline, null, 2));
  return baselinePath;
}

export function applyBaseline(findings, baseline) {
  const baselineSet = new Set(
    baseline.findings.map(f => `${f.signature}|${f.file}|${f.line}`)
  );

  let baselineMatchedCount = 0;
  const annotated = findings.map(f => {
    const key = `${f.signature}|${f.file}|${f.line}`;
    const isBaseline = baselineSet.has(key);
    if (isBaseline) baselineMatchedCount++;
    return { ...f, baseline: isBaseline };
  });

  return { annotated, baselineMatchedCount };
}
