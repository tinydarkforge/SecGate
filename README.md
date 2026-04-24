<!-- markdownlint-disable MD033 MD041 -->

```text
    ╔═══════╗        █████ █████ █████ █████ █████ █████ █████
    ║ ╔═══╗ ║        █     █     █     █     █   █   █   █
    ║ ║ ⊙ ║ ║        █████ ████  █     █ ███ █████   █   ████
    ║ ╚═══╝ ║            █ █     █     █   █ █   █   █   █
    ╠═══════╣        █████ █████ █████ █████ █   █   █   █████
    ║ ░░░░░ ║
╔═══╬═══════╬═══╗    ━━━━━━━━━━━━━ SECURITY GATE ━━━━━━━━━━━━━
║   ║ [===] ║   ║    Semgrep · Gitleaks · osv-scanner · Trivy
╚═══╬═══════╬═══╝    · npm audit  —  one command, one report,
    ║ ║   ║ ║        one exit code. MIT · No account · No tel.
    ╚═╝   ╚═╝
```

<p align="center">
  <a href="https://www.npmjs.com/package/@tinydarkforge/secgate"><img alt="npm" src="https://img.shields.io/npm/v/@tinydarkforge/secgate.svg?style=flat-square&labelColor=0a0a0a&color=00cc66"></a>
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/license-MIT-00cc66.svg?style=flat-square&labelColor=0a0a0a"></a>
  <img alt="node" src="https://img.shields.io/badge/node-%E2%89%A518-00cc66.svg?style=flat-square&labelColor=0a0a0a">
  <img alt="provenance" src="https://img.shields.io/badge/npm%20provenance-signed-00cc66.svg?style=flat-square&labelColor=0a0a0a">
  <a href="SECURITY.md"><img alt="security" src="https://img.shields.io/badge/security-policy-00cc66.svg?style=flat-square&labelColor=0a0a0a"></a>
  <a href="https://github.com/tinydarkforge/SecGate/actions/workflows/ci.yml"><img alt="self-scan" src="https://github.com/tinydarkforge/SecGate/actions/workflows/ci.yml/badge.svg?branch=main"></a>
</p>

> **SecGate** is a tiny security gate for CI/CD. Runs **Semgrep, Gitleaks, osv-scanner, Trivy, and npm audit** in one command, normalizes findings into one report, fails the pipeline on CRITICAL or HIGH. No account. No telemetry. Local files only.

> **Status:** Early release (`v0.2.4`). Published with [npm provenance](https://docs.npmjs.com/generating-provenance-statements). Report vulnerabilities via [SECURITY.md](SECURITY.md).

---

## ░▒▓█ TL;DR

```bash
npx @tinydarkforge/secgate .
```

Runs all five scanners against the current directory, writes a JSON report, a self-contained HTML report, and (optionally) SARIF. Exit `0` on clean, `1` on CRITICAL/HIGH findings. That's the whole product.

---

## ░▒▓█ What it does today

SecGate wraps five existing open-source scanners, runs them against a directory, and produces:

- **One normalized JSON report** across every scanner
- **One self-contained HTML report** with per-scanner tabs, dark mode, zero external assets
- **One SARIF 2.1.0 file** ready for GitHub Code Scanning upload
- **One exit code** — `1` when CRITICAL or HIGH findings are present; blocks CI

SecGate does not ship its own analysis engine. Every finding originates from one of the five underlying tools. The value is **orchestration, normalization, and a single exit code.**

---

## ░▒▓█ Scanners

| Scanner       | Category                  | Notes                                                                 |
|---------------|---------------------------|-----------------------------------------------------------------------|
| **Semgrep**   | SAST (static code)        | OSS ruleset. 10+ languages. Extend via `customSemgrepRules`.          |
| **Gitleaks**  | Secrets & credentials     | Working tree + git history (when `.git/` present). Secrets redacted.  |
| **npm audit** | Node dependencies (SCA)   | Runs when `package.json` present. GitHub advisory DB.                 |
| **osv-scanner** | Polyglot SCA            | npm, PyPI, Go, Cargo, Maven, RubyGems, Packagist, NuGet, Pub.         |
| **Trivy**     | IaC + License + Image     | Terraform, Kubernetes, Dockerfile, CloudFormation. Base-image CVEs.   |

Missing scanner binaries are **skipped gracefully** and noted in the report. No scanner is required; SecGate uses whatever is on `$PATH`.

---

## ░▒▓█ Positioning

SecGate is **not** a SOC platform, a compliance tool, or a vulnerability management system. It is a **CI gate** that aggregates scanner output and fails the build when something critical is found.

| Alternative        | When to pick it instead of SecGate                              |
|--------------------|-----------------------------------------------------------------|
| **Trivy standalone** | You only scan containers and don't need SAST or secrets.     |
| **Semgrep OSS**      | You only need SAST with custom rules.                        |
| **Snyk**             | You need a managed vuln DB, triage UX, Jira sync — and budget.|
| **Aikido**           | You want SaaS dashboards and are OK with a hosted account.   |

**SecGate's niche:** zero-config orchestration, no account, no telemetry, local output only, MIT. If you need SaaS-grade triage or compliance workflow, buy Snyk or Aikido. Full matrix: [`docs/comparison.md`](docs/comparison.md).

---

## ░▒▓█ Product vision

SecGate will become the open-source input layer for a broader security workflow. The **core CLI** — scan orchestration, SARIF output, baselines, suppressions, HTML report — stays **MIT-licensed and free, forever**. Future paid extensions may add hosted dashboards, org-wide policy management, compliance evidence packs, and multi-repo aggregation for teams that need more than a local gate. Those do not exist today. The OSS boundary is defined in [`OPEN-CORE.md`](OPEN-CORE.md).

---

## ░▒▓█ Prerequisites

Node.js `>=18`. External scanners are optional — install only the ones you want to run.

```bash
# macOS
brew install semgrep gitleaks osv-scanner trivy

# Linux
pip install semgrep
# gitleaks:    https://github.com/gitleaks/gitleaks#installing
# osv-scanner: https://github.com/google/osv-scanner#installation
# trivy:       https://aquasecurity.github.io/trivy/latest/getting-started/installation/
```

---

## ░▒▓█ Install

### From npm (recommended)

```bash
npm install -g @tinydarkforge/secgate
```

### One-shot via npx (no install)

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

## ░▒▓█ Usage

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

# Version / help
secgate --version
secgate --help
```

**Exit codes**

| Code | Meaning                                            |
|:----:|----------------------------------------------------|
| `0`  | PASS — no CRITICAL or HIGH findings                |
| `1`  | FAIL — CRITICAL or HIGH findings present           |
| `2`  | Invalid target or CLI error                        |

---

## ░▒▓█ Security — `--apply` in untrusted repos

> **⚠ `--apply` executes remediations (`npm audit fix`) inside the scanned repo.** Treat this as code execution against the target. **Only use it on code you trust.**

**Hardening already in place:**

- Every npm invocation under `--apply` passes `--ignore-scripts` — malicious `preinstall` / `postinstall` scripts in the target's `package.json` (or its dependencies) are **not executed**.
- `--apply` is **gated**: refuses to run unless `SECGATE_CONFIRM_APPLY=1` is set (CI / non-interactive) or the user types `y` at an interactive TTY prompt.
- Every `--apply` execution is recorded in the report's `auditLog` field and mirrored to stderr with timestamp and target.

**Operator guidance:**

- **Do not run `--apply` against untrusted or newly cloned third-party repos.** Run dry-run first, review, decide.
- In CI, prefer dry-run (`secgate .`) and rely on the exit code to gate. If you must `--apply`, do it inside an isolated, ephemeral runner with `SECGATE_CONFIRM_APPLY=1`.
- Report files default to the target directory. Use `--output-dir` to redirect; a warning is printed to stderr when `cwd !== target`.
- In CI, `--strip-paths` is auto-enabled to prevent host paths leaking into uploaded artifacts.

---

## ░▒▓█ Configuration

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

### Field reference

| Field                | Type            | Default                    | Description                                                                 |
|----------------------|-----------------|----------------------------|-----------------------------------------------------------------------------|
| `failOn`             | `string[]`      | `["critical","high"]`      | Severity tiers that cause exit `1`                                          |
| `scanners`           | `object`        | all `true`                 | Set any scanner to `false` to skip it                                       |
| `severityOverrides`  | `array`         | `[]`                       | Override severity for matching signatures (glob `*` supported)              |
| `ignore`             | `string[]`      | `[]`                       | Drop findings whose signature matches (glob `*` supported)                  |
| `baselineFile`       | `string`        | `.secgate-baseline.json`   | Path to baseline file (relative to target)                                  |
| `customSemgrepRules` | `string\|null` | `null`                     | Extra `--config=<path>` passed to semgrep                                   |

### Precedence

```
CLI flag  >  .secgate.config.json  >  built-in defaults
```

- `--baseline` and `--update-baseline` are CLI-only (no config equivalent).
- Missing config file: silent, defaults apply. Invalid JSON: error logged, defaults apply.

### Baseline workflow

```bash
# 1. Accept current state as baseline
secgate . --update-baseline

# 2. On subsequent runs, fail only on net-new findings
secgate . --baseline
```

Commit `.secgate-baseline.json` to your repo. Baselined findings appear in reports with a `baseline` marker and are excluded from the fail-gate.

### Inline suppression

Add a comment on the flagged line or the line immediately above:

```js
// secgate:ignore <rule-id>
db.query(userInput);

db.execute(sql); // secgate:ignore my.rule.id

/* secgate:ignore my.rule.id */
dangerousCall();
```

Suppressed findings are excluded from counters. The report's `suppressions` section records per-rule counts for audit.

---

## ░▒▓█ CI / CD

### GitHub Actions — minimal

```yaml
# .github/workflows/secgate.yml
- name: Run SecGate
  run: npx @tinydarkforge/secgate .
  # exits 1 on CRITICAL or HIGH findings — blocks the pipeline
```

### Non-blocking (report only)

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

### As a composite GitHub Action

A composite action is published at `.github/actions/secgate/` in this repo.

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

**Action inputs**

| Input     | Default          | Description                                              |
|-----------|------------------|----------------------------------------------------------|
| `target`  | `.`              | Directory to scan                                        |
| `apply`   | `false`          | Execute fixable remediations                             |
| `fail-on` | `critical,high`  | Severity levels that fail the step                       |
| `format`  | `json,html`      | Output formats — comma-separated: `json`, `html`, `sarif`|

**Action outputs**

| Output        | Description                                                   |
|---------------|---------------------------------------------------------------|
| `report-path` | Path to `secgate-v7-report.json`                              |
| `sarif-path`  | Path to `<repo>.sarif.json` (set only when format includes SARIF) |

**Pin to a full commit SHA** for production workflows:

```yaml
uses: tinydarkforge/SecGate/.github/actions/secgate@<full-sha>
```

See [`.github/workflows/example-secgate.yml`](.github/workflows/example-secgate.yml) for a complete reference workflow.

---

## ░▒▓█ SARIF output

SecGate emits [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) alongside JSON and HTML. SARIF is the standard format consumed by GitHub Code Scanning, GitLab SAST, and other platforms.

```bash
secgate . --format sarif
# writes: secgate-v7-report.json, <repo>.html, <repo>.sarif.json
```

The `--format` flag accepts a comma-separated list. `sarif` is **additive** — JSON and HTML are always written:

```bash
secgate . --format json,html,sarif   # same as above
secgate . --format sarif             # also writes JSON + HTML
```

### SARIF structure

- One `runs[]` entry per scanner: `semgrep`, `gitleaks`, `npm`, `osv`, `trivy`, `trivyImage` (6 total).
- Each finding maps to a `result` with `ruleId = signature`, `level` derived from severity, and `locations[].physicalLocation` when file/line data is present.
- `properties["security-severity"]` carries a CVSS-style score for GitHub's sort order: `CRITICAL = 9.5`, `HIGH = 7.5`, `MEDIUM = 5`, `LOW = 2`, `UNKNOWN = 0`.

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

## ░▒▓█ Report output

Each run writes:

- **`secgate-v7-report.json`** — machine-readable, schema below.
- **`<repo-name>.html`** — self-contained HTML report with per-scanner tabs, dark mode, zero external assets. Filename derived from the target directory name.
- **`<repo-name>.sarif.json`** — SARIF 2.1.0 file (only when `--format sarif` is passed).

### JSON schema

```json
{
  "version": "0.2.4",
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

Every finding is normalized to one of five tiers at the `addFinding()` ingress:

| Tier        | Meaning                                                                                  |
|-------------|------------------------------------------------------------------------------------------|
| **CRITICAL**| Exploitable now — secrets, CVSS ≥ 9, hardcoded-credential SAST rules                      |
| **HIGH**    | High-impact — CVSS 7.0–8.9, Semgrep `ERROR`, rated `HIGH` upstream                        |
| **MEDIUM**  | Meaningful — CVSS 4.0–6.9, `WARNING`, `MODERATE`                                          |
| **LOW**     | Informational — CVSS < 4.0, `INFO`, `NOTE`                                                |
| **UNKNOWN** | Upstream provided no severity or an unrecognized value — surfaced rather than miscounted |

### Fixability

- `fixableBy: "auto"` — `patch()` returns an executable command; `--apply` will run it (currently only `npm audit fix`).
- `fixableBy: "manual"` — a patch exists but requires human action (upgrade, rotate, refactor).
- `fixable: true` mirrors `fixableBy === "auto"` for CI convenience.

### Tool states

| State       | Meaning                                                                      |
|-------------|------------------------------------------------------------------------------|
| `ran`       | Tool executed, findings present                                              |
| `clean`     | Tool executed, no findings                                                   |
| `skipped`   | Tool not installed, or target not applicable (no `package.json`, no lockfile)|
| `error`     | Tool produced output that could not be parsed — re-run with `--debug`        |
| `pending`   | Tool did not run (should not appear in final reports)                        |

---

## ░▒▓█ Risk scoring

Findings are scored with static weights applied at ingress:

| Severity | Weight |
|----------|:------:|
| CRITICAL | 10     |
| HIGH     | 6      |
| MEDIUM   | 3      |
| LOW      | 1      |

The `riskScore` in the report is the sum of these weights across all findings. This is a **heuristic count**, not CVSS, not EPSS, not exploit-probability modeling. Use it to compare runs of the same repo over time — not as an absolute posture score.

---

## ░▒▓█ Documentation

| Doc                                                    | What's in it                                                                   |
|--------------------------------------------------------|--------------------------------------------------------------------------------|
| [`CHANGELOG.md`](CHANGELOG.md)                         | Version history — Added / Changed / Fixed / Security per release               |
| [`OPEN-CORE.md`](OPEN-CORE.md)                         | OSS core boundary and paid extension roadmap                                   |
| [`docs/comparison.md`](docs/comparison.md)             | Feature matrix vs Snyk / Trivy / Semgrep / Aikido                              |
| [`docs/coverage.md`](docs/coverage.md)                 | Scanner-to-category matrix, explicit gaps                                      |
| [`docs/tuning.md`](docs/tuning.md)                     | Thresholds, baselines, suppression, CI vs local defaults                       |
| [`docs/threat-model.md`](docs/threat-model.md)         | STRIDE analysis, trust boundaries, mitigations                                 |
| [`docs/adr/`](docs/adr/)                               | Architecture decision records                                                  |
| [`SECURITY.md`](SECURITY.md)                           | Vulnerability reporting, SLA, coordinated disclosure, supply-chain trust       |
| [`CONTRIBUTING.md`](CONTRIBUTING.md)                   | Dev setup, branch + commit conventions, PR checklist                           |

---

## ░▒▓█ Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Report vulnerabilities privately per [`SECURITY.md`](SECURITY.md) — **do not open public issues for security reports**.

---

## ░▒▓█ License

[MIT](LICENSE) — © TinyDarkForge

```text
            ╔═══╗
            ║ ⊙ ║   "BLOCK. SCAN. GATE."
            ╚═══╝
```
