# Tuning SecGate

How to adjust severity thresholds, baseline noisy findings, suppress rules, toggle scanners, and tune CI vs local defaults.

> Some flags referenced here (`--fail-on`, `--baseline`, `--disable`) are slated for the config epic [**#32**](https://github.com/tinydarkforge/SecGate/issues/32). Where a flag is planned but not yet shipped, this doc marks it **(planned)**.

---

## Severity Thresholds

### Default behavior

SecGate exits `1` on any **CRITICAL** or **HIGH** finding. MEDIUM and LOW findings are reported but do not fail the build.

### Custom threshold (planned #32)

```bash
# Only fail on CRITICAL
secgate . --fail-on critical

# Fail on MEDIUM and above (stricter)
secgate . --fail-on critical,high,medium

# Report only — never fail
secgate . --fail-on none
```

### Today — use exit-code masking

```bash
# Report only, don't fail CI
secgate . || true
```

---

## Baseline: Accepting Known Findings

Large existing codebases onboarding SecGate often have pre-existing findings that cannot be remediated immediately. A **baseline** records the current findings as acknowledged and fails the build only on *new* findings.

### Workflow (planned #32)

```bash
# 1. Initial scan records current state
secgate . --baseline-write .secgate-baseline.json

# 2. Subsequent scans diff against baseline
secgate . --baseline .secgate-baseline.json

# 3. A new CRITICAL finding not in baseline → exit 1
# 4. Review + regenerate baseline quarterly
```

Baseline file is a JSON list of finding **signatures** (rule ID + file path + line). Commit it to the repo.

### Today — use suppression comments

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

### Disable a scanner (planned #32)

```bash
# Skip Trivy (e.g., IaC not in scope for this repo)
secgate . --disable trivy

# Skip multiple
secgate . --disable trivy,npm
```

### Enable only one scanner (planned #32)

```bash
# Only run Semgrep
secgate . --only semgrep
```

### Today — use environment variable

```bash
# Force a scanner to "not installed" — it will be skipped
PATH="" SECGATE_SKIP=trivy secgate .    # planned
```

Today's workaround: temporarily uninstall the binary, or rely on the scanner being absent (SecGate skips missing binaries gracefully).

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

```bash
# Local
secgate . --fail-on critical,high,medium,low   # planned

# CI
# Same, no baseline needed (green field)
```

### Example 2 — Legacy repo, onboarding

You have a five-year-old repo with 200 pre-existing findings. You cannot fix them all in one PR but you want to prevent new ones.

```bash
# 1. First run — record baseline
secgate . --baseline-write .secgate-baseline.json

# 2. Commit baseline
git add .secgate-baseline.json
git commit -m "chore(security): establish secgate baseline"

# 3. All future PRs
secgate . --baseline .secgate-baseline.json
# → passes unless a NEW CRITICAL/HIGH appears

# 4. Quarterly cleanup: pick 20 findings, fix, regenerate baseline
```

### Example 3 — Monorepo with IaC in one subdir only

Your repo has `app/` (Node) and `infra/` (Terraform). You want Trivy only against `infra/`.

```bash
# Run twice with scoped targets
secgate app/ --disable trivy     # planned
secgate infra/ --only trivy      # planned

# Or — today — run against the whole repo and accept that Trivy scans every directory.
# SecGate's scoping today is path-based, not scanner-per-path.
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
