## Goal

Separate scan orchestration logic from the CLI wrapper and add baseline tests.

## Why

`secgate.js` is a 342-line monolith — all logic runs on import, nothing is importable. Blocks testing and future extension.

## Current State

Single file `secgate.js` with these logical sections (all top-level, not exported):
- `run()`, `toolExists()`, `debug()`, `addFinding()` — utils
- `gitleaks()`, `semgrep()`, `npmAudit()` — scanners (mutate global `findings` array)
- `analyze(findings)` — intelligence engine
- `remediate(findings)` — remediation planner
- Pipeline execution + `console.log` + `fs.writeFileSync` at top level

## Target File Layout

```
secgate.js          → thin CLI only (parse args, import src/, run pipeline, write report)
src/
  scanners.js       → export { gitleaks, semgrep, npmAudit }
  analyze.js        → export { analyze }
  remediate.js      → export { remediate }
test/
  scanners.test.js
  analyze.test.js
  fixtures/
    empty-scan.json        → { findings: [] }
    vuln-scan.json         → { findings: [{tool:"npm",type:"dependency",severity:"HIGH",...}] }
    critical-scan.json     → { findings: [{tool:"gitleaks",type:"secret",severity:"CRITICAL",...}] }
```

## Module Contracts

**`src/scanners.js`** — each scanner takes `target` string, returns `Finding[]`, does NOT mutate globals:
```js
// Finding shape (stable — do not change)
{
  tool: string,       // "gitleaks" | "semgrep" | "npm"
  type: string,       // "secret" | "code" | "dependency"
  severity: string,   // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  signature: string,
  message: string,
  fixable: boolean
}

export function gitleaks(target) { ... }   // returns Finding[]
export function semgrep(target) { ... }    // returns Finding[]
export function npmAudit(target) { ... }   // returns Finding[]
```

**`src/analyze.js`**:
```js
export function analyze(findings) { ... }  // returns intelligence object
```

**`src/remediate.js`**:
```js
export function remediate(findings, target, apply) { ... }  // returns remediation object
```

**`secgate.js`** (thin CLI after refactor):
```js
#!/usr/bin/env node
import { gitleaks, semgrep, npmAudit } from './src/scanners.js'
import { analyze } from './src/analyze.js'
import { remediate } from './src/remediate.js'
// parse args, run, write report, exit
```

## Tests

Use `node:test` (builtin — zero new deps).

**`test/analyze.test.js`** — pure functions, no external tools needed:
```js
import { test } from 'node:test'
import assert from 'node:assert'
import { analyze } from '../src/analyze.js'

test('empty findings → riskScore 0', () => {
  const r = analyze([])
  assert.equal(r.riskScore, 0)
})

test('CRITICAL finding → high risk score', () => {
  const findings = [{ severity: 'CRITICAL', type: 'secret', signature: 'x', tool: 'gitleaks', message: '', fixable: false }]
  const r = analyze(findings)
  assert.ok(r.riskScore >= 10)
})
```

**`test/scanners.test.js`** — test missing-tool behavior (tool absent = returns `[]`, does not throw):
```js
import { test } from 'node:test'
import assert from 'node:assert'
// mock toolExists to return false, verify scanners return []
```

## Verify Commands

```bash
node --test                    # all tests pass
node secgate.js . && echo OK   # CLI still works end-to-end
```

## Acceptance Criteria

- `import { analyze } from './src/analyze.js'` works without side effects
- `node --test` runs and passes
- Missing external tool (`semgrep`, `gitleaks`) → scanner returns `[]`, no throw
- Report JSON shape unchanged from v7 (same keys)
- `secgate.js` CLI behavior identical to before refactor

## Scope

Do NOT add new scanner features. Do NOT change report JSON shape. Refactor only.
