# SecGate

Tiny open-source security gate for CI/CD pipelines.

Orchestrates [Semgrep](https://semgrep.dev), [Gitleaks](https://github.com/gitleaks/gitleaks), [osv-scanner](https://github.com/google/osv-scanner), [Trivy](https://github.com/aquasecurity/trivy), and `npm audit` — aggregates findings, scores risk, generates fix plans, renders a premium HTML report with per-scanner tabs, and blocks pipelines on critical issues.

> **Status:** Early release. Published with [npm provenance](https://docs.npmjs.com/generating-provenance-statements). See [SECURITY.md](SECURITY.md) to report vulnerabilities.

---

## Features

**Multi-layer scanning**
- Semgrep — static code analysis (SAST)
- Gitleaks — secret and credential detection
- npm audit — dependency vulnerability scanning (when `package.json` present)
- osv-scanner — polyglot SCA (npm, PyPI, Go, Cargo, Maven, RubyGems, Packagist, NuGet, Pub)
- Trivy — IaC misconfiguration + license scanning (Terraform, Kubernetes, Dockerfile, CloudFormation)

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
- Premium self-contained HTML report (`<repo-name>.html`) — dark-mode, zero external assets
- Works in GitHub Actions, GitLab CI, Jenkins

---

## Prerequisites

SecGate requires Node.js >=18. External scanners are optional — missing tools are skipped and noted in the report.

```bash
# macOS
brew install semgrep gitleaks osv-scanner trivy

# Linux
pip install semgrep
# gitleaks:      https://github.com/gitleaks/gitleaks#installing
# osv-scanner:   https://github.com/google/osv-scanner#installation
# trivy:         https://aquasecurity.github.io/trivy/latest/getting-started/installation/
```

---

## Installation

### From npm (recommended)

```bash
npm install -g @tinydarkforge/secgate
```

Or one-shot via `npx` (no install):

```bash
npx @tinydarkforge/secgate .
```

### From source

```bash
git clone https://github.com/tinydarkforge/SecGate.git
cd SecGate
npm install
chmod +x secgate.js
sudo ln -sf "$(pwd)/secgate.js" /usr/local/bin/secgate
```

---

## Usage

```bash
# Scan current directory (dry-run, default)
secgate .

# Scan with auto-remediation
secgate . --apply

# Scan with debug output
secgate . --debug

# Scan specific path
secgate /path/to/project

# Show version
secgate --version

# Show help
secgate --help
```

Exit codes:
- `0` — PASS (no CRITICAL or HIGH findings)
- `1` — FAIL (CRITICAL or HIGH findings present)
- `2` — invalid target or CLI error

---

## CI/CD Example

```yaml
# .github/workflows/secgate.yml
- name: Run SecGate
  run: npx @tinydarkforge/secgate .
  # exits 1 on CRITICAL or HIGH findings — blocks the pipeline
```

For non-blocking (report only):
```yaml
- name: Run SecGate
  run: npx @tinydarkforge/secgate . || true

- name: Upload report
  uses: actions/upload-artifact@v4
  with:
    name: secgate-report
    path: |
      secgate-v7-report.json
      *.html
```

---

## Report output

Each run writes two files:

- **`secgate-v7-report.json`** — machine-readable report (schema below).
- **`<repo-name>.html`** — premium self-contained HTML report with per-scanner tabs, dark-mode UI, zero external assets. Filename is derived from the target directory name.

### JSON schema

```json
{
  "version": "0.1.0",
  "timestamp": "ISO 8601",
  "target": "/absolute/path",
  "mode": "dry-run | apply",
  "status": "PASS | FAIL",
  "summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "unknown": 0
  },
  "tools": {
    "semgrep":  "ran | clean | skipped | error | pending",
    "gitleaks": "ran | clean | skipped | error | pending",
    "npm":      "ran | clean | skipped | error | pending",
    "osv":      "ran | clean | skipped | error | pending",
    "trivy":    "ran | clean | skipped | error | pending"
  },
  "findings": [
    {
      "tool": "gitleaks | semgrep | npm | osv | trivy",
      "type": "secret | code | dependency | iac | license",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN",
      "signature": "rule or package ID",
      "message": "description",
      "file": "relative or absolute path, or null",
      "line": 42,
      "col": 5,
      "endLine": 42,
      "fixable": false,
      "fixableBy": "auto | manual | null"
    }
  ],
  "intelligence": {
    "riskScore": 0,
    "attackSurface": ["secret", "dependency", "iac", "license", "code"],
    "reasoning": [{ "issue": "...", "why": "..." }],
    "recommendations": ["..."]
  },
  "remediation": {
    "plan": [{
      "issue": "...",
      "patch": {
        "action": "...",
        "cmd": "display string or null",
        "exec": { "binary": "npm", "args": ["audit", "fix"], "cwd": "..." }
      }
    }],
    "stagedChanges": [],
    "executed": [],
    "blocked": [],
    "confidence": 100
  }
}
```

### Severity tiers

Every finding is normalized to one of 5 tiers at the `addFinding()` ingress:

- **CRITICAL** — exploitable now (secrets, CVSS ≥ 9, hardcoded-credential SAST rules)
- **HIGH** — high-impact (CVSS 7.0–8.9, Semgrep `ERROR`, rated `HIGH` upstream)
- **MEDIUM** — meaningful (CVSS 4.0–6.9, `WARNING`, `MODERATE`)
- **LOW** — informational (CVSS < 4.0, `INFO`, `NOTE`)
- **UNKNOWN** — upstream provided no severity or an unrecognized value; surfaced explicitly rather than silently miscounted

### Fixability

- `fixableBy: "auto"` — `patch()` returns an executable command; `--apply` will run it (currently only `npm audit fix`).
- `fixableBy: "manual"` — a patch exists but requires human action (upgrade, rotate, refactor).
- `fixable: true` mirrors `fixableBy === "auto"` for CI convenience.

### Tool states

- **`ran`** — tool executed, findings present.
- **`clean`** — tool executed, no findings.
- **`skipped`** — tool not installed, or target not applicable (no `package.json` for npm audit, no lockfile, etc.).
- **`error`** — tool produced output that could not be parsed (re-run with `--debug` to inspect).
- **`pending`** — tool did not run (should not appear in final reports).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities per [SECURITY.md](SECURITY.md).

---

## License

[MIT](LICENSE) — TinyDarkForge
