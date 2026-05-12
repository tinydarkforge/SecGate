## Goal

Make the package easy to trust, install, and consume in CI.

## Why

A public security tool lives or dies on installation friction, release hygiene, and reproducible behavior.

## Prerequisite

Issue 02 must be merged first — tests must exist before CI can run them.

## Exact Files to Create

### `.github/workflows/ci.yml`

```yaml
name: CI

on:
  push:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: node --test
```

### `.github/workflows/release.yml`

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          registry-url: 'https://registry.npmjs.org'
      - run: npm publish --provenance --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

### `.npmrc`

```
provenance=true
```

### `docs/prerequisites.md`

Document these required external tools (secgate degrades gracefully when absent):

| Tool | Install | Used for |
|------|---------|----------|
| `semgrep` | `brew install semgrep` / `pip install semgrep` | SAST code scanning |
| `gitleaks` | `brew install gitleaks` | Secret detection |
| `npm` | bundled with Node.js | Dependency audit |

Note: if tool is missing, that scanner returns no findings. Scan still runs.

### `docs/ci-example.yml`

Minimal GitHub Actions example users can copy:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  secgate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install -g secgate
      - run: secgate .
```

## Verify

- Push to a branch → CI runs `node --test` → passes
- Tag `v1.0.1` → release workflow triggers (dry run: confirm workflow parses, don't actually publish yet)

## Acceptance Criteria

- CI runs on every push and PR
- Release workflow exists and is valid YAML
- `docs/prerequisites.md` exists with tool table
- `docs/ci-example.yml` is copy-pasteable

## Scope

Do NOT add linting (no eslint config exists). Tests only. Operational polish only.
