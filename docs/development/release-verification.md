# Release verification

Every cryptkey release ships three things for each supported platform:

- The binary archive (`cryptkey-vX.Y.Z-<os>-<arch>.tar.gz`)
- A CycloneDX JSON SBOM (`cryptkey-vX.Y.Z-<os>-<arch>.tar.gz.sbom.json`)
- A checksums file (`checksums.txt`) covering every archive and SBOM, signed via cosign (`checksums.txt.sig` + `checksums.txt.pem`)

The release is produced by [.github/workflows/build.yml](https://github.com/ekristen/cryptkey/blob/master/.github/workflows/build.yml) on tag push. No long-lived signing keys are used — cosign keyless signing via GitHub Actions OIDC (Fulcio + Rekor) anchors trust to the workflow identity.

## Verifying a release

You need [cosign](https://github.com/sigstore/cosign) installed. Distillery installs it for you; if you downloaded a binary manually, `brew install cosign` / the [official installer](https://docs.sigstore.dev/system_config/installation/) work.

### 1. Verify the checksums file

```bash
cosign verify-blob \
  --certificate=checksums.txt.pem \
  --signature=checksums.txt.sig \
  --certificate-identity-regexp='^https://github.com/ekristen/cryptkey/\.github/workflows/build\.yml' \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  checksums.txt
```

What this checks:

- The signature was made by a GitHub Actions token issued to a workflow in `ekristen/cryptkey`.
- The certificate was minted by Fulcio (Sigstore's CA) during the release build.
- An entry exists in the public Rekor transparency log (cosign verifies this automatically).

Tighten the identity regex further if you want to pin a specific branch or tag:

```bash
--certificate-identity-regexp='^https://github.com/ekristen/cryptkey/\.github/workflows/build\.yml@refs/tags/'
```

### 2. Verify your archive against the checksums

```bash
# Pick the platform archive you downloaded, e.g. linux-amd64.
grep cryptkey-vX.Y.Z-linux-amd64.tar.gz checksums.txt | sha256sum -c -
```

`sha256sum -c -` prints `cryptkey-vX.Y.Z-linux-amd64.tar.gz: OK` on match, a non-zero exit and `FAILED` on mismatch.

### 3. Verify the SBOM (optional)

The SBOM's sha256 is in `checksums.txt`, so the same verification chain covers it:

```bash
grep cryptkey-vX.Y.Z-linux-amd64.tar.gz.sbom.json checksums.txt | sha256sum -c -
```

Cryptkey does **not** sign SBOMs individually with cosign. The single-signature-over-checksums.txt model is enough: once you trust `checksums.txt` via cosign, every file listed in it is provable by sha256. This trades "one-step SBOM verification" for "half as many artifacts on the release page."

## Inspecting the SBOM

The SBOM is [CycloneDX JSON](https://cyclonedx.org/specification/overview/). Read it with any CycloneDX-aware tool, or just with `jq`:

```bash
# Top-level metadata.
jq '.metadata' cryptkey-vX.Y.Z-linux-amd64.tar.gz.sbom.json

# Go modules compiled into the binary.
jq '.components[] | select(.type == "library")' cryptkey-vX.Y.Z-linux-amd64.tar.gz.sbom.json

# Scan for known CVEs (requires Grype or similar).
grype sbom:./cryptkey-vX.Y.Z-linux-amd64.tar.gz.sbom.json
```

The SBOM catalogs what syft can see from the static binary's embedded Go module table plus the archive contents. The C-side build-time dependencies (libfido2, libcbor, libpcsclite, musl) aren't in the Go module table and therefore aren't in the SBOM. Those are pinned by the build script and documented in [Static Builds](static-builds.md).

## Why this shape

- **Single cosign signature, transitive trust.** One `cosign verify-blob` on `checksums.txt`, then standard `sha256sum -c` on anything else. Simpler than per-file signatures and sufficient for release-consumer workflows.
- **Keyless signing, no key management.** The Fulcio certificate names the workflow that produced it, so "this binary came from the cryptkey release pipeline" is provable without any long-lived key cryptkey has to rotate, protect, or revoke.
- **SBOM always present, never decoupled.** Adding an SBOM beside each archive means downstream tools (Grype, Dependency-Track, compliance scanners) can work directly against a release tarball without having to re-scan the binary. The checksums file covers it so authenticity doesn't depend on fetching anything else.
- **Matches the goreleaser / distillery convention** (minus the per-SBOM signatures), so any tooling written against that convention works here too.
