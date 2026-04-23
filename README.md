# SecGate

Open-source security scanning and remediation CLI for CI/CD pipelines.

Orchestrates [Semgrep](https://semgrep.dev), [Gitleaks](https://github.com/gitleaks/gitleaks), and `npm audit` — aggregates findings, scores risk, generates fix plans, and blocks pipelines on critical issues.

> **Status:** Working prototype. Not production-ready for enterprise use.

---

## Features

**Multi-layer scanning**
- Semgrep — static code analysis (SAST)
- Gitleaks — secret and credential detection
- npm audit — dependency vulnerability scanning (when `package.json` present)

**Risk intelligence**
- Weighted scoring: CRITICAL=10, HIGH=6, MEDIUM=3, LOW=1
- Attack surface classification by finding type
- Exploitability reasoning and prioritized recommendations

**Remediation engine**
- Auto-generated fix plans per finding
- Confidence scoring
- Dry-run by default; `--apply` executes fixable remediations (`npm audit fix`)

**CI/CD integration**
- Exit code `0` — PASS (no CRITICAL or HIGH findings)
- Exit code `1` — FAIL (CRITICAL or HIGH findings present)
- JSON report output (`secgate-v7-report.json`)
- Works in GitHub Actions, GitLab CI, Jenkins

---

## Prerequisites

SecGate requires Node.js >=18. External scanners are optional — missing tools are skipped and noted in the report.

```bash
# macOS
brew install semgrep gitleaks

# Linux
pip install semgrep
# gitleaks: https://github.com/gitleaks/gitleaks#installing
```

---

## Installation

```bash
git clone https://github.com/tinydarkforge/SecGate.git
cd SecGate
npm install
```

Add to PATH (optional):
```bash
chmod +x secgate.js
sudo ln -sf "$(pwd)/secgate.js" /usr/local/bin/secgate
```

---

## Usage

```bash
# Scan current directory (dry-run, default)
node secgate.js .

# Scan with auto-remediation
node secgate.js . --apply

# Scan with debug output
node secgate.js . --debug

# Scan specific path
node secgate.js /path/to/project
```

---

## CI/CD Example

```yaml
# .github/workflows/secgate.yml
- name: Run SecGate
  run: node secgate.js .
  # exits 1 on CRITICAL or HIGH findings — blocks the pipeline
```

For non-blocking (report only):
```yaml
- name: Run SecGate
  run: node secgate.js . || true

- name: Upload report
  uses: actions/upload-artifact@v4
  with:
    name: secgate-report
    path: secgate-v7-report.json
```

---

## Report Schema

Output written to `secgate-v7-report.json` after each run:

```json
{
  "version": "7.0",
  "timestamp": "ISO 8601",
  "target": ".",
  "mode": "dry-run | apply",
  "status": "PASS | FAIL",
  "summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "findings": [
    {
      "tool": "gitleaks | semgrep | npm",
      "type": "secret | code | dependency",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "signature": "rule or package ID",
      "message": "description",
      "fixable": true
    }
  ],
  "intelligence": {
    "riskScore": 0,
    "attackSurface": ["secret", "dependency"],
    "reasoning": [{ "issue": "...", "why": "..." }],
    "recommendations": ["..."]
  },
  "remediation": {
    "plan": [{ "issue": "...", "patch": { "action": "...", "cmd": null } }],
    "stagedChanges": [],
    "executed": [],
    "blocked": [],
    "confidence": 100
  }
}
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities per [SECURITY.md](SECURITY.md).

---

## License

[MIT](LICENSE) — TinyDarkForge
