# Changelog

All notable changes to SecGate are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) + [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

### Security

### Deprecated

### Removed

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
