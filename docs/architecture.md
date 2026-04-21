# Architecture

## Overview

Cryptkey's design centers on two principles: **no single point of failure** and **no stored secrets**. It achieves this by combining Shamir's Secret Sharing with provider-specific key derivation.

## Data Flow

### Enrollment (`init`)

```
                    ┌─────────────┐
                    │ Generate    │
                    │ Master Key  │ (32 random bytes)
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │   Shamir    │
                    │   Split     │ (n shares, threshold t)
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼─────┐ ┌───▼───┐ ┌─────▼─────┐
        │ Provider A │ │ Prov B│ │ Provider C │
        │ (secret)   │ │(secret│ │ (secret)   │
        └─────┬─────┘ └───┬───┘ └─────┬─────┘
              │            │            │
        ┌─────▼─────┐ ┌───▼───┐ ┌─────▼─────┐
        │ HKDF →    │ │ HKDF →│ │ HKDF →    │
        │ AES-GCM   │ │AES-GCM│ │ AES-GCM   │
        │ Encrypt   │ │Encrypt│ │ Encrypt   │
        └─────┬─────┘ └───┬───┘ └─────┬─────┘
              │            │            │
              └────────────┼────────────┘
                           │
                    ┌──────▼──────┐
                    │  HMAC       │ (integrity over all shares)
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Save TOML  │
                    │  Profile    │
                    └─────────────┘
                           │
                    ┌──────▼──────┐
                    │ Wipe master │
                    │ key + shares│
                    └─────────────┘
```

### Reconstruction (`derive`)

```
        ┌─────────────┐ ┌─────────┐ ┌─────────────┐
        │ Provider A   │ │ Prov B  │ │ Provider C   │
        │ re-derive    │ │re-derive│ │ re-derive    │
        │ secret       │ │ secret  │ │ secret       │
        └──────┬──────┘ └────┬────┘ └──────┬──────┘
               │              │              │
        ┌──────▼──────┐ ┌────▼────┐          │
        │ Decrypt     │ │ Decrypt │  (only t needed)
        │ share       │ │ share   │
        └──────┬──────┘ └────┬────┘
               │              │
               └──────┬───────┘
                      │
               ┌──────▼──────┐
               │   Shamir    │
               │   Combine   │ (t shares → master key)
               └──────┬──────┘
                      │
               ┌──────▼──────┐
               │ Verify HMAC │
               └──────┬──────┘
                      │
               ┌──────▼──────┐
               │ HKDF derive │
               │ output key  │
               └─────────────┘
```

## Cryptographic Primitives

| Operation | Algorithm | Parameters |
|-----------|-----------|------------|
| Master key | `crypto/rand` | 32 bytes |
| Secret sharing | Shamir over GF(256) | threshold-of-n |
| Share encryption | AES-256-GCM | Key via HKDF |
| Key derivation | HKDF-SHA256 | 32-byte salt, context-specific info string |
| Passphrase stretching | Argon2id | Configurable; default t=3, m=256 MiB, p=4 (derive-time floor is OWASP's t=2, m=19 MiB, p=1) |
| Config integrity | HMAC-SHA256 | Key derived via HKDF from master key |

## Shamir's Secret Sharing

The implementation operates over GF(256) (the Galois field with 256 elements). This means:

- Each byte of the master key is split independently
- Shares are the same length as the secret (32 bytes)
- Any `t` shares can reconstruct the secret; `t-1` shares reveal **zero information** (information-theoretic security — not breakable even with infinite computing power)
- No share is more "important" than another
- The minimum threshold is 2 (threshold 1 would be equivalent to storing the key in plaintext)

The field arithmetic uses lookup tables for multiplication and discrete logarithm to avoid timing side channels.

See [Security — Shamir Threshold Security](security.md#shamir-threshold-security) for a detailed explanation of the security guarantees and threshold planning guidance.

## Share Encryption

Each provider's Shamir share is encrypted with AES-256-GCM:

1. Generate a random 32-byte salt
2. Derive an AES-256 key: `HKDF-SHA256(provider_secret, salt, "cryptkey-share-encryption")`
3. Generate a random GCM nonce
4. Encrypt the share with AES-256-GCM (nonce + ciphertext + authentication tag)
5. Store the ciphertext, nonce, and salt in the profile

The Additional Authenticated Data (AAD) for GCM is `"<provider_type>:<provider_id>"`, binding the ciphertext to a specific provider slot.

## Memory Safety

Cryptkey explicitly zeroes sensitive data after use:

- Master key bytes are wiped after Shamir splitting and HMAC computation
- Provider secrets are wiped after share encryption/decryption
- Shamir shares are wiped after combining
- Passphrase buffers are wiped after Argon2 derivation
- `runtime.KeepAlive()` prevents the compiler from optimizing away the wipe

!!! note "Best-effort guarantee"
    Go's garbage collector may copy heap objects during compaction, leaving prior copies in freed memory pages. Wiping is therefore a best-effort mitigation that raises the bar for memory forensics but cannot fully prevent it in a GC'd runtime. Cryptkey's [secrets-as-`[]byte` discipline](https://github.com/ekristen/cryptkey/blob/master/CLAUDE.md) — carrying plaintext through `[]byte` end-to-end rather than Go strings, so every intermediate copy can be zeroed — narrows the window that actually exists.

## Provider Model

All providers implement a simple interface:

```go
type Provider interface {
    Type() string
    Description() string
    Enroll(ctx context.Context, id string) (*EnrollResult, error)
    Derive(ctx context.Context, params map[string]string) ([]byte, error)
}
```

- **Enroll** produces a 32-byte secret and metadata. The secret encrypts the provider's share; the metadata is stored for later re-derivation.
- **Derive** reproduces the same 32-byte secret using the stored metadata.

Providers self-register via Go's `init()` mechanism. The main binary imports them for side effects.

## Profile Format

Profiles are TOML files stored at `~/.config/cryptkey/<name>.toml`:

```toml
version = 1
name = "myprofile"
threshold = 2
output_salt = "d4e5f6..."  # hex-encoded random salt for HKDF output key derivation
integrity = "a1b2c3..."    # HMAC-SHA256 hex (covers all fields including threshold)

[[providers]]
type = "passphrase"
id = "passphrase-1"
encrypted_share = "..."  # AES-256-GCM ciphertext hex
nonce = "..."             # GCM nonce hex
share_salt = "..."        # HKDF salt hex

[providers.params]
salt = "..."              # Argon2 salt hex

[[providers]]
type = "sshkey"
id = "laptop-key"
encrypted_share = "..."
nonce = "..."
share_salt = "..."

[providers.params]
salt = "..."
fingerprint = "SHA256:..."
path = "/home/user/.ssh/id_ed25519"
```
