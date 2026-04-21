# cryptkey

Cryptkey uses [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) to protect encryption keys behind multiple authentication providers. You choose which providers to enroll — hardware security keys, passphrases, recovery codes, SSH keys — and only a threshold of them is needed to reconstruct your key.

No single provider compromise reveals the key. No single provider loss locks you out.

## Quick Start

```bash
# Install via distillery (https://dist.sh) — portable static binary from
# GitHub releases, no Go toolchain or libfido2 needed at runtime.
dist install ekristen/cryptkey

# Launch the TUI and enroll providers into the "default" profile.
# Enroll at least 3 so any 2 can unlock — e.g. two passphrases plus a
# recovery code, or a FIDO2 key plus a passphrase plus a recovery code.
# Omitting the profile name uses "default" for every cryptkey command.
cryptkey init

# Derive the key — authenticate with any threshold of providers
cryptkey derive

# Pipe the key to another tool on stdin (preferred over --env)
cryptkey derive --raw -- my-tool --key-file /dev/stdin

# List profiles
cryptkey list

# Show profile details
cryptkey info
```

Pass a name (e.g. `cryptkey init work`) when you want more than one profile.
Other install options (direct binary download, `go install`, source build) — see the [Getting Started](docs/getting-started.md) guide.

## Providers

| Provider | Type | Description |
|----------|------|-------------|
| FIDO2 | `fido2` | Hardware security key (YubiKey, SoloKey, etc.) via `hmac-secret` |
| Passkey | `passkey` | Browser-based WebAuthn passkey with PRF extension |
| Passphrase | `passphrase` | Argon2id-derived key from a memorized passphrase |
| Recovery Code | `recovery` | One-time generated code — print and store safely |
| SSH Key | `sshkey` | Secret derived from an existing SSH private key |
| SSH Agent | `ssh-agent` | Secret derived from SSH agent signing (Ed25519 only) |
| TPM | `tpm` | TPM 2.0 sealed secret (Linux only) |
| Secure Enclave | `secure-enclave` | **Not supported** — macOS only, no plans to implement |

> **Note:** Secure Enclave access on macOS requires a provisioning profile. Bare CLI binaries have no way to obtain a provisioning profile to access the Secure Enclave — the CLI would need to be wrapped in an app bundle. There are no plans to ship a version packaged this way.

## How It Works

1. Each provider produces a **32-byte secret** from its own key material
2. A random master key is split into shares using **Shamir's Secret Sharing**
3. Each share is encrypted with its provider's secret (**AES-256-GCM** via **HKDF-SHA256**)
4. Only the encrypted shares and metadata are stored — **the master key is never saved**

To unlock: authenticate with enough providers to meet the threshold, decrypt their shares, and recombine.

## Building

```bash
# Default: fully-static portable binary for the current OS (matches releases)
make

# Fast dev build with dynamic linking (requires libfido2-dev at build time)
make build

# Run tests
make test
```

See [Static Builds](docs/development/static-builds.md) for the full toolchain story.

## Documentation

Full documentation is available at [ekristen.github.io/cryptkey](https://ekristen.github.io/cryptkey) or can be served locally:

```bash
make docs-serve
```

## Security

- Master key is never stored on disk
- Shares are encrypted with AES-256-GCM
- Profile integrity is verified with HMAC-SHA256
- Secrets are explicitly zeroed in memory after use
- Passphrases are stretched with Argon2id (64 MiB, 3 iterations)

See [Security Model](https://ekristen.github.io/cryptkey/security/) for the full threat model and cryptographic details.

## License

See [LICENSE](LICENSE) for details.
