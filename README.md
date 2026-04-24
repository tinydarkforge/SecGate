# SecGate

Scan orchestrator for CI/CD pipelines. Runs Semgrep, Gitleaks, osv-scanner, Trivy, and npm audit in one command, normalizes findings into a single report, and blocks the pipeline on critical issues.

> **Status:** Early release (v0.2.3). Published with [npm provenance](https://docs.npmjs.com/generating-provenance-statements). See [SECURITY.md](SECURITY.md) to report vulnerabilities.

---

## What it does today

SecGate wraps five existing open-source scanners, runs them against a directory, and produces:

- One normalized JSON report across all scanners
- One self-contained HTML report with per-scanner tabs
- One SARIF 2.1.0 file for GitHub Code Scanning upload
- Exit code 1 when CRITICAL or HIGH findings are found — blocks CI

It does not run its own analysis engine. Every finding originates from one of the five underlying tools. SecGate's value is the orchestration, normalization, and single exit code.

---

## Scanners

- **Semgrep** — static code analysis (SAST)
- **Gitleaks** — secret and credential detection
- **npm audit** — Node dependency vulnerabilities (when `package.json` present)
- **osv-scanner** — polyglot SCA (npm, PyPI, Go, Cargo, Maven, RubyGems, Packagist, NuGet, Pub)
- **Trivy** — IaC misconfiguration + license scanning (Terraform, Kubernetes, Dockerfile, CloudFormation) + container base-image vulnerability scanning

Missing tools are skipped and noted in the report. No scanner is required.

---

## Positioning

SecGate is not a SOC platform, a compliance tool, or a vulnerability management system. It is a CI gate that aggregates scanner output and fails the build when something critical is found.

Nearest alternatives:

- **Trivy standalone** — better for container image scanning; no SAST or secrets bundling
- **Semgrep OSS** — better custom SAST rules; no SCA or secrets
- **Snyk** — managed vulnerability DB, triage UX, Jira sync; requires account, costs money
- **Aikido** — bundled SaaS alternative; requires account, telemetry

SecGate's niche: zero-config orchestration, no account, no telemetry, local output only, MIT license. If you need SaaS-grade triage, dashboards, or compliance workflow, Snyk or Aikido are the right buy. Full comparison: [`docs/comparison.md`](docs/comparison.md).

---

## Product vision

SecGate will become the open-source input layer for a broader security workflow. The core CLI — scan orchestration, SARIF output, baseline/suppression, HTML report — stays MIT-licensed and free. Future paid extensions will add hosted dashboards, org-wide policy management, compliance evidence packs, and multi-repo aggregation for teams that need more than a local gate. Those features do not exist today. The OSS boundary is defined in [OPEN-CORE.md](OPEN-CORE.md).

---

## Prerequisites

Node.js >= 18. External scanners are optional.

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

# Scan with auto-remediation (npm audit fix only — see warning below)
secgate . --apply

# Scan with debug output
secgate . --debug

# Scan specific path
secgate /path/to/project

# Write reports to a custom directory (default: the target)
secgate /path/to/project --output-dir /tmp/reports

# Strip absolute paths from the report (auto-on when CI=true)
secgate /path/to/project --strip-paths

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

## Security: `--apply` in untrusted repos

`--apply` executes remediations (`npm audit fix`) inside the scanned repo. Treat this as code execution against the target — only use it on code you trust.

Hardening:
- SecGate passes `--ignore-scripts` to every npm invocation under `--apply`, so malicious `preinstall`/`postinstall` scripts in the target repo's `package.json` or its dependencies are not executed.
- `--apply` is gated: it refuses to run unless either `SECGATE_CONFIRM_APPLY=1` is set (for CI/non-interactive use) or the user confirms `y` at an interactive TTY prompt.
- Every `--apply` execution is recorded in the report's `auditLog` field and mirrored to stderr with timestamp + target.

Guidance:
- **Do not run `--apply` against untrusted or newly cloned third-party repos.** Run scans in dry-run mode first, review findings, then decide.
- In CI, prefer dry-run (`secgate .`) and rely on the exit code to gate the pipeline. Only use `--apply` with `SECGATE_CONFIRM_APPLY=1` inside an isolated, ephemeral runner.
- Report files default to the target directory. Use `--output-dir` to redirect explicitly; a warning is printed to stderr when `cwd !== target`.
- In CI, `--strip-paths` is auto-enabled to prevent host paths from leaking into uploaded artifacts.

---

## Configuration

Create `.secgate.config.json` in your scan target directory. All fields are optional.

```json
{
  "failOn": ["critical", "high"],
  "scanners": {
    "semgrep": true,
    "gitleaks": true,
    "npm": true,
    "osv": true,
    "trivy": false
  },
  "severityOverrides": [
    { "rule": "npm-audit.lodash", "severity": "LOW" },
    { "rule": "trivy-DS*", "severity": "MEDIUM" }
  ],
  "ignore": ["CVE-2024-12345", "npm:some-old-package*"],
  "baselineFile": ".secgate-baseline.json",
  "customSemgrepRules": "./rules/"
}
```

JSON Schema: [`docs/config.schema.json`](docs/config.schema.json)

### Config field reference

| Field | Type | Default | Description |
|---|---|---|---|
| `failOn` | `string[]` | `["critical","high"]` | Severity tiers that cause exit 1 |
| `scanners` | `object` | all `true` | Set any scanner to `false` to skip it |
| `severityOverrides` | `array` | `[]` | Override severity for matching signatures (glob `*` supported) |
| `ignore` | `string[]` | `[]` | Drop findings whose signature matches (glob `*` supported) |
| `baselineFile` | `string` | `.secgate-baseline.json` | Path to baseline file (relative to target) |
| `customSemgrepRules` | `string\|null` | `null` | Extra `--config=<path>` argument passed to semgrep |

### Precedence

```
CLI flag  >  .secgate.config.json  >  built-in defaults
```

- `--baseline` and `--update-baseline` are CLI-only (no config equivalent).
- `failOn` in config is overridden per-run if you pass a custom exit-code wrapper in CI.
- Missing config file: silent, defaults apply. Invalid JSON: error logged, defaults apply.

### Baseline workflow

```bash
# 1. Accept current state as baseline
secgate . --update-baseline

# 2. On subsequent runs, fail only on net-new findings
secgate . --baseline
```

The baseline file (`.secgate-baseline.json`) should be committed to your repo. Findings present in the baseline are shown in reports with a `baseline` marker and excluded from the fail-gate.

### Inline suppression

Add a comment on the flagged line or the line immediately above:

```js
// secgate:ignore <rule-id>
db.query(userInput);

db.execute(sql); // secgate:ignore my.rule.id

/* secgate:ignore my.rule.id */
dangerousCall();
```

Suppressed findings are excluded from counters. The report includes a `suppressions` section with per-rule counts for audit purposes.

---

## CI/CD example

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

## SARIF output (`--format sarif`)

SecGate emits a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) report alongside the default JSON+HTML output. SARIF is the standard format consumed by GitHub Code Scanning, GitLab SAST, and other platforms.

```bash
secgate . --format sarif
# writes: secgate-v7-report.json, <repo-name>.html, <repo-name>.sarif.json
```

The `--format` flag accepts a comma-separated list. `sarif` is additive — JSON and HTML are always written:

```bash
secgate . --format json,html,sarif   # same as above
secgate . --format sarif             # also writes JSON+HTML
```

### SARIF structure

- One `runs[]` entry per scanner (semgrep, gitleaks, npm, osv, trivy, trivyImage — 6 total).
- Each finding maps to a `result` with `ruleId` = signature, `level` derived from severity, and `locations[].physicalLocation` when file/line data is present.
- `properties["security-severity"]` carries a numeric CVSS-style score for GitHub Code Scanning sort order: CRITICAL=9.5, HIGH=7.5, MEDIUM=5, LOW=2, UNKNOWN=0.

### Upload to GitHub Code Scanning

```yaml
- name: Run SecGate
  id: secgate
  run: npx @tinydarkforge/secgate . --format sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: <repo-name>.sarif.json
    category: secgate
```

---

## Use as a GitHub Action

A composite action is published in this repository at `.github/actions/secgate/`.

```yaml
- name: SecGate Security Gate
  id: secgate
  uses: tinydarkforge/SecGate/.github/actions/secgate@main
  with:
    target: "."
    apply: "false"
    fail-on: "critical,high"
    format: "json,html,sarif"

- name: Upload HTML + JSON
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: secgate-report
    path: |
      secgate-v7-report.json
      *.html

- name: Upload SARIF to Code Scanning
  if: always() && steps.secgate.outputs.sarif-path != ''
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.secgate.outputs.sarif-path }}
    category: secgate
```

**Action inputs:**

| Input | Default | Description |
|-------|---------|-------------|
| `target` | `.` | Directory to scan |
| `apply` | `false` | Execute fixable remediations |
| `fail-on` | `critical,high` | Severity levels that fail the step |
| `format` | `json,html` | Output formats (comma-separated: json, html, sarif) |

**Action outputs:**

| Output | Description |
|--------|-------------|
| `report-path` | Path to `secgate-v7-report.json` |
| `sarif-path` | Path to `<repo>.sarif.json` (set only when format includes `sarif`) |

**Pinned SHA recommendation:** For production workflows, pin to a full commit SHA rather than `@main`:

```yaml
uses: tinydarkforge/SecGate/.github/actions/secgate@<full-sha>
```

See `.github/workflows/example-secgate.yml` in this repository for a complete reference workflow.

---

## Report output

Each run writes:

- **`secgate-v7-report.json`** — machine-readable report (schema below).
- **`<repo-name>.html`** — self-contained HTML report with per-scanner tabs, dark-mode UI, zero external assets. Filename is derived from the target directory name.
- **`<repo-name>.sarif.json`** — SARIF 2.1.0 file (only when `--format sarif` is passed).

### JSON schema

```json
{
  "version": "0.2.3",
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
    "semgrep":    "ran | clean | skipped | error | pending",
    "gitleaks":   "ran | clean | skipped | error | pending",
    "npm":        "ran | clean | skipped | error | pending",
    "osv":        "ran | clean | skipped | error | pending",
    "trivy":      "ran | clean | skipped | error | pending",
    "trivyImage": "ran | clean | skipped | error | pending"
  },
  "findings": [
    {
      "tool": "gitleaks | semgrep | npm | osv | trivy | trivyImage",
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
        "exec": { "binary": "npm", "args": ["audit", "fix", "--ignore-scripts"], "cwd": "..." }
      }
    }],
    "stagedChanges": [],
    "executed": [],
    "blocked": [],
    "confidence": 100
  },
  "auditLog": [
    {
      "timestamp": "ISO 8601",
      "event": "apply_start | apply_confirmed | apply_exec | apply_ok | apply_fail",
      "target": "target path or repo basename (if --strip-paths)"
    }
  ]
}
```

### Severity tiers

Every finding is normalized to one of 5 tiers at the `addFinding()` ingress:

- **CRITICAL** — exploitable now (secrets, CVSS >= 9, hardcoded-credential SAST rules)
- **HIGH** — high-impact (CVSS 7.0-8.9, Semgrep `ERROR`, rated `HIGH` upstream)
- **MEDIUM** — meaningful (CVSS 4.0-6.9, `WARNING`, `MODERATE`)
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

## Risk scoring

Findings are scored with static weights applied at ingress: CRITICAL=10, HIGH=6, MEDIUM=3, LOW=1. The `riskScore` in the report is the sum of these weights across all findings. This is a simple heuristic count — it is not CVSS, not EPSS, and not exploit-probability modeling. Use it to compare runs of the same repo over time, not as an absolute security posture score.

---

## Documentation

- [`OPEN-CORE.md`](OPEN-CORE.md) — OSS core boundary and paid extension roadmap
- [`docs/comparison.md`](docs/comparison.md) — full feature matrix vs Snyk / Trivy / Semgrep / Aikido
- [`docs/threat-model.md`](docs/threat-model.md) — STRIDE analysis, trust boundaries, mitigations
- [`docs/coverage.md`](docs/coverage.md) — scanner-to-category matrix, explicit gaps
- [`docs/tuning.md`](docs/tuning.md) — thresholds, baselines, suppression, CI vs local defaults
- [`docs/adr/`](docs/adr/) — architecture decision records (scanner stack, auto-fix scope, dry-run default, report format, no-API stance)
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting, SLA, coordinated disclosure

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities per [SECURITY.md](SECURITY.md).

---

## License

[MIT](LICENSE) — TinyDarkForge
