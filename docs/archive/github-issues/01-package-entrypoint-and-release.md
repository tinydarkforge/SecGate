## Goal

Make SecGate a credible npm package with the current engine as the published entrypoint.

## Why

`package.json` bin points to `index.js` (v4, dead code). Real engine is `secgate.js` (v7). Publishing now ships the wrong binary.

## Current State

```json
// package.json — WRONG
{
  "name": "secgate",
  "version": "1.0.0",
  "bin": { "secgate": "index.js" },
  "type": "module"
}
```

- `index.js` = v4 engine (outdated, not maintained)
- `secgate.js` = v7 engine (current, correct)

## Exact Changes

**1. Fix `package.json`:**

```json
{
  "name": "secgate",
  "version": "1.0.0",
  "description": "Security scan orchestration and remediation guidance for CI pipelines",
  "keywords": ["security", "sast", "secrets", "npm-audit", "ci"],
  "license": "MIT",
  "type": "module",
  "engines": { "node": ">=18" },
  "files": ["secgate.js"],
  "bin": { "secgate": "secgate.js" }
}
```

**2. Delete `index.js`** — dead code, v4 engine, not wired anywhere.

**3. Verify shebang exists** in `secgate.js` line 1: `#!/usr/bin/env node`

## Verify Commands

```bash
node secgate.js . && echo "PASS"
npm pack --dry-run   # should list only secgate.js + package.json
```

## Acceptance Criteria

- `npm install -g .` installs working `secgate` command
- `secgate .` runs v7 engine
- `npm pack --dry-run` only includes `secgate.js`
- `package.json` has all metadata fields above

## Scope

Do NOT refactor `secgate.js` internals. Packaging fix only.
