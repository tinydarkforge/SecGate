Perform a security scan on the target directory. Target = $ARGUMENTS if provided, else current working directory (`.`).

## Step 1 — Detect tools

```bash
which semgrep 2>/dev/null && echo "semgrep:ok" || echo "semgrep:missing"
which gitleaks 2>/dev/null && echo "gitleaks:ok" || echo "gitleaks:missing"
which npm 2>/dev/null && echo "npm:ok" || echo "npm:missing"
```

If ALL missing: report it, list install commands, stop.

## Step 2 — Run scanners (only tools that exist)

**semgrep:**
```bash
semgrep --config=auto --json <target> 2>/dev/null
```
Parse `.results[]` → `check_id`=signature, `extra.severity`=severity, `extra.message`=message, `path`+`start.line`=location.

**gitleaks:**
```bash
gitleaks detect --source <target> --report-format json --report-path /tmp/gl.json 2>/dev/null
cat /tmp/gl.json 2>/dev/null || echo "[]"
```
Parse array → `RuleID`=signature, `Description`=message, `File`+`StartLine`=location. All severity = CRITICAL.

**npm audit** (only if `<target>/package.json` exists):
```bash
cd <target> && npm audit --json 2>/dev/null
```
Parse `.vulnerabilities` → key=package, `severity`, `title`. Map: `critical`→CRITICAL, `high`→HIGH, else MEDIUM.

## Step 3 — Verify findings

Read flagged files with the Read tool. Mark each finding confirmed or likely-false-positive based on actual code context.

## Step 4 — Score

CRITICAL=10pts, HIGH=6pts, MEDIUM=3pts, LOW=1pt. Sum = risk score.

## Step 5 — Print report

```
═══════════════════════════════════
 SECGATE SECURITY SCAN
 Target: <target>
 Date:   <ISO timestamp>
═══════════════════════════════════

TOOLS: semgrep ✓  gitleaks ✓  npm-audit ✓
STATUS: PASS | FAIL
RISK SCORE: <n>

FINDINGS (<n> total)
─────────────────────
[CRITICAL] <signature>
  Tool:     <tool>
  Location: <file>:<line>
  Issue:    <message>
  Fix:      <specific step>

[HIGH] ...
[MEDIUM] ...

SUMMARY
───────
Critical: <n>  High: <n>  Medium: <n>  Low: <n>

RECOMMENDATIONS
───────────────
1. <most urgent>
2. ...

MISSING TOOLS (if any)
──────────────────────
<tool>: brew install <tool> | pip install <tool>
```

Zero findings → print `NO FINDINGS — clean scan`.

## Step 6 — Final status

- Any CRITICAL or HIGH → `SCAN FAILED — review before merging`
- Otherwise → `SCAN PASSED`

## Rules

- Never fabricate findings
- Read flagged files before confirming a finding
- Recommendations must be specific commands, not generic advice
