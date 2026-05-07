# Changelog

All notable changes to SecGate are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) + [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Confidence profiles for the HTML report.** New `profile` config field
  (`"curated"` default, `"strict"` opt-in) and matching `--profile` CLI flag.
  Curated profile demotes known-noisy patterns to a collapsed Informational
  details block instead of mixing them with actionable findings:
  - Trivy `type: license` findings (governance, not security)
  - Trivy base-image OS CVEs at LOW/MEDIUM (`scanMode: image` or
    `signature: trivy-image:*`) — rarely reachable from app runtime
  - CVEs >5 years old, severity != CRITICAL — upstream-bounded exploitability
  - `UNKNOWN` severity findings — scanner couldn't classify
  - `html.security.audit.missing-integrity` Semgrep rule — fires on every
    `<script src>` including inline favicon SVGs
  - `path-join-resolve-traversal` Semgrep rule — common false positive in
    CLI tools that legitimately resolve user-supplied paths
  Real-world impact: 2,628-file production codebase scan went from 1,858
  raw findings → 46 actionable (98% demoted). Demotion is display-only;
  the `failOn` policy alone gates CI exit code.
- **Suppressed findings details block.** Findings dropped via inline
  `# secgate:ignore` comments now get their own collapsed block with
  per-rule counts in the HTML report (still excluded from counters).
- **`.secgate.config.example.json`** — fully-commented example config
  shipped at repo root; copy into your repo and edit.
- **19 new unit tests** in `test/confidence.mjs` covering all demotion
  paths (license, image-scan via tool/scanMode/signature, stale-CVE year
  arithmetic, profile bypass).
- **Sidebar shell parity with luxfaber + lucen.** SecGate report now
  renders in the unified Midnight Blossom / Dawn Blossom shell shared
  across the three TinyDarkForge products. 240px sticky sidebar with
  brand block + score + band pill + PASS/FAIL chip + scroll-spy nav.
  Theme toggle persisted in `localStorage`. 🛡 inline SVG favicon.

### Changed
- HTML report `Findings` section meta line now reads
  `N actionable · M informational · K suppressed` instead of raw total,
  matching the curated/strict bucket split.
- Tab labels show `<actionable> +<informational>` (e.g. `npm audit  3 +5`)
  so demoted findings remain discoverable per-tool.
- Sidebar `Reasoning` and `Remediation` nav counts now reflect filtered
  (actionable-only) item counts. Previously they showed the per-finding
  upstream count, which made the sidebar inconsistent with the Findings
  count under curated profile.

### Documentation
- README: new "What we demote (and why)" section + `profile` row in
  config reference table + JSON example + `--profile` CLI usage.
- Landing page: new "What we don't pretend" section listing curated
  profile, suppression UX, and the no-exploitability-oracle limit;
  real-world reduction stat (1,858 → 46) cited inline.
- `docs/tuning.md`: new "Confidence Profiles" section before Severity
  Thresholds; reflects v0.2.6 behavior.
- `docs/config.schema.json`: new `profile` enum field with description.
- `DESIGN_PARITY.md`: SecGate added as third sister product alongside
  luxfaber + lucen.

---

## [0.2.6] — 2026-05-07

### Fixed
- Release workflow now installs external scanners (Semgrep, Gitleaks, osv-scanner,
  Trivy) before running smoke tests. Previously the build job ran `npm test`
  without scanners, causing the `vulnerable-dockerfile fixture → trivy detects
  misconfig` smoke test to fail in CI while passing locally.

### Note
- `v0.2.5` was tagged but never published to npm or GitHub Releases due to the
  CI bug above. All `v0.2.5` content is included in `v0.2.6`.

---

## [0.2.5] — 2026-05-07

### Fixed
- `excludePaths` now matches against repo-relative paths, so absolute lockfile paths
  reported by osv-scanner (e.g. fixtures, vendored trees) are correctly excluded
  instead of leaking into scan results.
- `runTrivyImage` Dockerfile discovery honors `excludePaths`, preventing fixture
  Dockerfiles from being scanned as base images outside test mode.

### Security
- Suppressed two false-positive Semgrep findings on internal `path.resolve` and
  `RegExp` helpers (target dir / glob compiler — not user-controlled).

---

## [0.2.4] — 2026-04-24

### Changed
- Refreshed README with updated ASCII CLI banner and corrected `--tuning` flag documentation.

---

## [0.2.3] — 2026-04-23

No functional changes. Patch release to validate CI/CD pipeline configuration after v0.2.2.

---

## [0.2.2] — 2026-04-23

### Fixed
- `runTool()` was mixing stdout and stderr on non-zero exit codes. Now returns stdout only, preventing scanner noise from polluting parsed output.

---

## [0.2.1] — 2026-04-23

### Added
- Core engine extracted into `lib/` modules for testability.
- Scanner fixture tests and end-to-end smoke test suite.
- Trivy image scanning mode documented in README.

---

## [0.2.0] — 2026-04-23

### Added
- `.secgate.json` config file: severity thresholds, scope patterns, tool toggles, tuning presets.
- Baseline workflow: suppress known findings by committing a signed baseline snapshot.
- Inline `secgate-ignore` suppression comments for per-finding exceptions.
- SARIF 2.1.0 output format (`--format sarif`) for GitHub Code Scanning integration.
- Composite GitHub Action (`.github/actions/secgate`) for zero-config consumer integration.
- Trivy image scanning mode (`--mode image`) and no-lockfile detection finding.
- Documentation bundle: threat model, scanner coverage matrix, tuning guide, tool comparison, ADRs.

### Changed
- **Breaking:** findings schema overhauled — each finding now carries `location` (file, line, col) and structured `severity` fields. Consumers parsing the JSON report must update selectors.

### Security
- GitHub Releases now include CycloneDX SBOM, SLSA L3 provenance attestation, and cosign keyless signatures on tarball and SBOM.
- Hardened `--apply` flag against path traversal attacks.
- Sanitized file paths in HTML and JSON reports to prevent path leak to downstream consumers.

### Fixed
- Skipped-tool reason now shown clearly in report output (was previously blank for missing tools).

---

## [0.1.0] — 2026-04-23

Initial public release to npm as `@tinydarkforge/secgate`.

### Added
- Five scanner integrations: Semgrep (SAST), Gitleaks (secrets), npm audit (dependency CVEs), osv-scanner (OSV database), Trivy (CVEs + misconfigs).
- Per-tool scanner status tracking in report (`ok`, `skipped`, `error`).
- Normalized JSON findings report (`secgate-v7-report.json`) with unified severity tiers (CRITICAL / HIGH / MEDIUM / LOW / INFO).
- Tabbed HTML report with per-scanner breakdown.
- npm publish with provenance (`--provenance`).
- Risk scoring and exit code semantics: exit `0` = clean or low/medium only; exit `1` = CRITICAL or HIGH findings present.

[Unreleased]: https://github.com/tinydarkforge/SecGate/compare/v0.2.4...HEAD
[0.2.4]: https://github.com/tinydarkforge/SecGate/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/tinydarkforge/SecGate/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/tinydarkforge/SecGate/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/tinydarkforge/SecGate/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/tinydarkforge/SecGate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tinydarkforge/SecGate/releases/tag/v0.1.0
