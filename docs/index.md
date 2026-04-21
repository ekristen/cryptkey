# cryptkey

Cryptkey is a CLI tool that uses [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) to protect encryption keys behind multiple authentication providers. You choose which providers to enroll — hardware security keys, passphrases, recovery codes, SSH keys — and only a threshold of them is needed to reconstruct your key.

## How It Works

1. **Enroll** providers (FIDO2 keys, passphrases, recovery codes, SSH keys, etc.)
2. Each provider produces a **32-byte secret** from its own key material
3. A random **master key** is generated and split into shares using Shamir's scheme
4. Each share is **encrypted** with its provider's secret (AES-256-GCM via HKDF)
5. The encrypted shares and metadata are saved to a **TOML profile** on disk
6. The master key is **wiped from memory** — it is never stored

To reconstruct the key later, you authenticate with enough providers to meet the threshold. Their secrets decrypt their respective shares, Shamir recombines the shares, and the master key is recovered.

## Why?

- **No single point of failure** — losing one provider doesn't lock you out
- **No single point of compromise** — stealing one provider doesn't give access
- **Flexible** — mix hardware keys with passphrases, recovery codes, and SSH keys
- **Offline** — no servers, no accounts, no network required
- **Composable** — pipe the derived key into any tool that needs one

## Quick Start

```bash
# Install via distillery (https://dist.sh) — grabs a portable static binary
# from GitHub releases, no Go toolchain or libfido2 required at runtime.
dist install ekristen/cryptkey

# Create a profile with two passphrases + a recovery code, threshold 2.
# Any two of the three unlock the key; losing one is survivable.
# Omitting the profile name uses "default" (most commands fall back to
# it when no name is given).
cryptkey init --add passphrase --add passphrase --add recovery

# Derive the key — any two providers unlock it
cryptkey derive

# Pipe the key to another tool on stdin (preferred over env var)
cryptkey derive --raw -- my-tool --key-file /dev/stdin
```

See [Getting Started](getting-started.md) for interactive mode, hardware keys, more providers, named profiles, and alternative install methods (direct release download, `go install`, source build).

## Providers

| Provider | Type | Description |
|----------|------|-------------|
| [FIDO2](providers/fido2.md) | `fido2` | Hardware security key (YubiKey, SoloKey, etc.) |
| [Passkey](providers/passkey.md) | `passkey` | Browser-based WebAuthn passkey with PRF extension |
| [Passphrase](providers/passphrase.md) | `passphrase` | Argon2id-derived key from a memorized passphrase |
| [Recovery Code](providers/recovery.md) | `recovery` | One-time generated code — print it and store safely |
| [SSH Key](providers/sshkey.md) | `sshkey` | Secret derived from an existing SSH private key |
| [SSH Agent](providers/sshagent.md) | `ssh-agent` | Secret derived from SSH agent signing (Ed25519 only) |
| [TPM](providers/tpm.md) | `tpm` | Hardware-bound secret via TPM 2.0 HMAC key (Linux only) |
| Secure Enclave | `secure-enclave` | **Not supported** — macOS only, no plans to implement |

> **Note:** Secure Enclave access on macOS requires a provisioning profile. Bare CLI binaries have no way to obtain a provisioning profile to access the Secure Enclave — the CLI would need to be wrapped in an app bundle. There are no plans to ship a version packaged this way.

## Multiple Keys From One Profile

The `--use` flag lets you derive multiple independent keys from the same profile:

```bash
cryptkey derive myprofile                # default key
cryptkey derive myprofile --use disk     # a different key for disk encryption
cryptkey derive myprofile --use backups  # another for encrypting backups
```

Each `--use` label produces a completely different 256-bit key via [HKDF](https://datatracker.ietf.org/doc/html/rfc5869) domain separation. Knowing one derived key reveals nothing about any other — or the master key. This lets you manage a single set of providers and threshold while deriving as many purpose-specific keys as you need. See [derive --use](commands/derive.md#purpose-specific-keys) for details.

## Security Model

- Master key is never stored on disk — only encrypted Shamir shares
- Each share is encrypted with AES-256-GCM using a key derived via HKDF-SHA256
- Profile integrity is verified with HMAC-SHA256 (keyed by the master key)
- Secrets are explicitly zeroed in memory after use
- All sensitive prompts suppress terminal echo
