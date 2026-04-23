# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SecGate, please report it privately.

**Do not open a public GitHub issue for security reports.**

Preferred channel:
- Open a [private security advisory](https://github.com/tinydarkforge/SecGate/security/advisories/new) on GitHub.

Include:
- A description of the vulnerability and its impact
- Steps to reproduce
- Affected version(s)
- Any suggested remediation

We will acknowledge receipt within 72 hours and aim to provide an initial assessment within 7 days.

## Supported Versions

Only the latest `main` branch receives security fixes at this stage.

## Scope

SecGate is a security scanning engine itself. Please report:
- Bypasses of the scanning/remediation logic
- Unsafe handling of scan artifacts, secrets, or intermediate files
- Supply-chain concerns in declared dependencies
- Any path traversal, command injection, or privilege escalation paths

Out of scope:
- Findings in third-party scanners invoked by SecGate (report upstream)
- Misconfiguration in end-user CI environments

## Supply-chain trust

Every tagged release (`vX.Y.Z`) ships with verifiable provenance:

| Artifact | Filename pattern | Purpose |
|---|---|---|
| Release tarball | `secgate-X.Y.Z.tgz` | Signed build of the npm package |
| CycloneDX SBOM | `secgate-X.Y.Z.sbom.cdx.json` | Full dependency manifest (CycloneDX 1.5+) |
| cosign signature | `*.sig`, `*.pem`, `*.cosign.bundle` | Keyless Sigstore signature over tarball and SBOM |
| SLSA L3 attestation | `secgate-vX.Y.Z.intoto.jsonl` | Non-falsifiable build provenance (SLSA v1.0, Level 3) |
| Checksums | `SHA256SUMS` | SHA-256 manifest for tarball + SBOM |

npm registry metadata also carries [npm provenance](https://docs.npmjs.com/generating-provenance-statements)
(via `publishConfig.provenance: true`) for the `@tinydarkforge/secgate` package.

### Trust root (keyless cosign)

SecGate uses **keyless cosign** via Sigstore and GitHub OIDC — there is no
long-lived signing key to steal or rotate. Verification binds the artifact to
the exact workflow that produced it:

- Expected OIDC issuer: `https://token.actions.githubusercontent.com`
- Expected signer identity (regex):
  `^https://github\.com/tinydarkforge/SecGate/\.github/workflows/release\.yml@refs/tags/.*`

The Sigstore transparency log (Rekor) entry is the public record. There is no
"public key" to rotate; if the signer identity or issuer ever changes, that is
the signal, and release notes will call it out.

### One-line verification

```bash
curl -fsSL https://raw.githubusercontent.com/tinydarkforge/SecGate/main/scripts/verify-release.sh \
  | bash -s -- v0.1.0
```

Or from a clone:

```bash
scripts/verify-release.sh v0.1.0
```

The script verifies: SBOM presence + CycloneDX shape, SHA256SUMS, cosign
keyless signature on tarball + SBOM, and SLSA L3 provenance on both.

### Manual verification

Install [`cosign`](https://docs.sigstore.dev/system_config/installation) (>=
2.0) and [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier) (>=
2.4), then:

```bash
VERSION=v0.1.0
BASE="https://github.com/tinydarkforge/SecGate/releases/download/${VERSION}"
TARBALL="secgate-${VERSION#v}.tgz"
SBOM="secgate-${VERSION#v}.sbom.cdx.json"
ATT="secgate-${VERSION}.intoto.jsonl"

for f in "$TARBALL" "${TARBALL}.sig" "${TARBALL}.pem" "${TARBALL}.cosign.bundle" \
         "$SBOM" "$ATT" SHA256SUMS; do
  curl -fsSLO "${BASE}/${f}"
done

# 1. Checksums
sha256sum -c SHA256SUMS

# 2. cosign keyless signature on the tarball
cosign verify-blob \
  --bundle "${TARBALL}.cosign.bundle" \
  --certificate "${TARBALL}.pem" \
  --signature "${TARBALL}.sig" \
  --certificate-identity-regexp \
    '^https://github\.com/tinydarkforge/SecGate/\.github/workflows/release\.yml@refs/tags/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$TARBALL"

# 3. SLSA L3 provenance
slsa-verifier verify-artifact \
  --provenance-path "$ATT" \
  --source-uri github.com/tinydarkforge/SecGate \
  --source-tag "$VERSION" \
  "$TARBALL"
```

### Release gate

The release workflow fails closed: the GitHub Release is not published, and
npm publish does not run, if either the SBOM or SLSA attestation is missing
or empty. cosign signatures are likewise gated before release assets are
uploaded.

If verification fails for an artifact you downloaded, **do not install it** —
open a private security advisory immediately.
