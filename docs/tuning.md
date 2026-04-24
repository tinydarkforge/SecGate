```text
░▒▓█ SECGATE · TUNING █▓▒░
```

# Tuning SecGate

How to adjust severity thresholds, baseline noisy findings, suppress rules, toggle scanners, and tune CI vs local defaults.

> Flags marked **(planned)** are not yet shipped; the rest of this document reflects `v0.2.3` behavior. The config epic tracking remaining work: [**#32**](https://github.com/tinydarkforge/SecGate/issues/32).

---

## Severity Thresholds

### Default behavior

SecGate exits `1` on any **CRITICAL** or **HIGH** finding. MEDIUM and LOW findings are reported but do not fail the build.

### Custom threshold

Set `failOn` in `.secgate.config.json`:

```json
{ "failOn": ["critical"] }                      // only fail on CRITICAL
{ "failOn": ["critical", "high", "medium"] }    // stricter
{ "failOn": [] }                                // report only — never fail
```

### Alternative — exit-code masking

```bash
# Report only, don't fail CI
secgate . || true
```

---

## Baseline: Accepting Known Findings

Large existing codebases onboarding SecGate often have pre-existing findings that cannot be remediated immediately. A **baseline** records the current findings as acknowledged and fails the build only on *new* findings.

### Workflow

```bash
# 1. Record current state as baseline
secgate . --update-baseline

# 2. Subsequent scans diff against baseline, failing only on net-new findings
secgate . --baseline

# 3. A new CRITICAL finding not in baseline → exit 1
# 4. Review + regenerate baseline quarterly
```

Baseline file defaults to `.secgate-baseline.json` in the target directory (override via `baselineFile` in config). It is a JSON list of finding **signatures** (rule ID + file path + line). Commit it to the repo.

### Complementary — inline suppression

See next section.

---

## Suppression Syntax

Inline suppression disables a rule for a specific line or block.

### Line comment

```javascript
const token = "AKIA..."; // secgate:ignore gitleaks-aws-access-key
```

```python
password = "test"  # secgate:ignore gitleaks-generic-api-key
```

### Block comment

```javascript
/* secgate:ignore semgrep-javascript-lang-eval-detected */
const result = eval(input);
```

### Multiple rules

```javascript
// secgate:ignore gitleaks-github-pat, semgrep-javascript-crypto-weak-ssl
```

### Placement

- **Same line** as the finding — most reliable.
- **Line above** — accepted.
- **Block comment preceding** — applies to the next statement.

### What it does

SecGate filters suppressed findings out of the report before severity rollup. They do not count toward fail thresholds. They still appear in the HTML report under a "Suppressed" section so reviewers can audit them.

### Rule IDs

Use the rule ID from the JSON report (`findings[].signature` field). Copy-paste from a dry run.

---

## Per-Scanner Toggles

### Disable scanners via config

```json
{
  "scanners": {
    "semgrep":  true,
    "gitleaks": true,
    "npm":      true,
    "osv":      true,
    "trivy":    false
  }
}
```

Any scanner set to `false` is skipped and reported as `status: "skipped"`. To run only one scanner, disable the rest.

### Alternative — remove the binary

SecGate skips any scanner whose binary is not on `$PATH` (reported as `skipped` with reason `binary not found`). Useful when you control the CI image — install only the scanners you want to run.

CLI flags `--disable <list>` and `--only <scanner>` are planned — see [#32](https://github.com/tinydarkforge/SecGate/issues/32).

---

## CI vs Local Defaults

| Setting | Local dev | CI |
|---------|-----------|----|
| Mode | `--apply` after review | dry-run (default) |
| Threshold | `--fail-on critical,high,medium` (strict while developing) | `--fail-on critical,high` (default) |
| Baseline | Not used — see every issue | Used — only fail on new |
| Output | Human-readable summary + HTML | JSON artifact + HTML uploaded |
| Scanner set | All | All |
| Timeout | CLI default | Add job-level timeout (15–30 min) |
| Clone depth | Full | `fetch-depth: 0` for secrets history |

### Recommended CI config (GitHub Actions)

```yaml
jobs:
  secgate:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history for gitleaks

      - name: Install scanners
        run: |
          brew install semgrep gitleaks osv-scanner trivy || \
          (pip install semgrep && \
           curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/install.sh | sh && \
           curl -sSfL https://raw.githubusercontent.com/google/osv-scanner/main/scripts/install.sh | sh && \
           curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh)

      - name: Run SecGate
        run: npx @tinydarkforge/secgate .

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: secgate-report
          path: |
            secgate-v7-report.json
            *.html
```

---

## Worked Examples

### Example 1 — New repo, strict mode

You are starting a green-field repo and want every issue caught.

```json
// .secgate.config.json
{ "failOn": ["critical", "high", "medium", "low"] }
```

No baseline needed (green field). Same config in CI and local.

### Example 2 — Legacy repo, onboarding

You have a five-year-old repo with 200 pre-existing findings. You cannot fix them all in one PR but you want to prevent new ones.

```bash
# 1. First run — record baseline
secgate . --update-baseline

# 2. Commit baseline
git add .secgate-baseline.json
git commit -m "chore(security): establish secgate baseline"

# 3. All future PRs
secgate . --baseline
# → passes unless a NEW CRITICAL/HIGH appears

# 4. Quarterly cleanup: fix a batch of findings, regenerate baseline
secgate . --update-baseline
```

### Example 3 — Monorepo with IaC in one subdir only

Your repo has `app/` (Node) and `infra/` (Terraform). You want Trivy only against `infra/`.

```bash
# Today — two configs, two runs
# app/.secgate.config.json          → { "scanners": { "trivy": false } }
# infra/.secgate.config.json        → { "scanners": { "semgrep": false, "gitleaks": false, "npm": false, "osv": false } }

secgate app/
secgate infra/

# Or run against the whole repo and accept that every scanner scans every
# directory. Scoping today is path-based, not scanner-per-path.
# CLI equivalents (--disable, --only) planned: #32.
```

---

## Debugging

```bash
# Verbose scanner output + parse failures
secgate . --debug

# Inspect raw JSON
cat secgate-v7-report.json | jq '.findings[] | select(.severity=="CRITICAL")'

# Check tool status
cat secgate-v7-report.json | jq '.tools'
```

If a scanner reports `"error"` state, re-run with `--debug` to see the raw stdout/stderr that failed to parse.

---

See also: [`coverage.md`](coverage.md), [`threat-model.md`](threat-model.md), [`adr/0003-dry-run-default.md`](adr/0003-dry-run-default.md).
