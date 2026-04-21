# SSH Key Provider

The SSH key provider derives a 32-byte secret from an existing SSH private key using HKDF-SHA256.

**Type:** `sshkey`

## Requirements

- An SSH private key file (Ed25519, ECDSA, or RSA)
- The key file must be accessible at derive time

## How It Works

### Enrollment

1. The user provides the path to an SSH private key
2. If the key is passphrase-protected, the passphrase is prompted
3. The private key is parsed and canonically marshaled
4. A random 32-byte salt is generated
5. HKDF derives the secret: `HKDF-SHA256(key_material, salt, "cryptkey-ssh-provider") → 32 bytes`
6. The key's SHA256 fingerprint, salt, and file path are stored in the profile
7. Private key bytes are wiped from memory

### Derivation

1. The stored key path is used to read the SSH private key (or the user provides an override)
2. The key's fingerprint is verified against the stored fingerprint
3. The same HKDF derivation reproduces the 32-byte secret

## Usage

```bash
# Interactive TUI
cryptkey init
# Select "sshkey" from the menu
# Enter the key path when prompted (default: ~/.ssh/id_ed25519)

# Non-interactive — path as the ID
cryptkey init --no-tui \
  --add sshkey:~/.ssh/id_ed25519 \
  --add passphrase:backup

# Derive — key path is remembered from enrollment
cryptkey derive
```

## Stored Parameters

| Parameter | Description |
|-----------|-------------|
| `salt` | Hex-encoded 32-byte HKDF salt |
| `fingerprint` | SSH SHA256 fingerprint (e.g., `SHA256:abc123...`) |
| `path` | File path to the key (used as default during derivation) |

## Supported Key Types

| Type | Format |
|------|--------|
| Ed25519 | 32-byte seed (private key material only) |
| ECDSA | DER-encoded EC private key |
| RSA | DER-encoded PKCS#1 private key |

## Key Path Resolution

During enrollment, the key path is determined by (in order):

1. Context value (TUI pre-collected)
2. The provider ID, if it looks like a file path (starts with `/`, `~`, or `.`)
3. Interactive prompt (defaults to `~/.ssh/id_ed25519`)

During derivation, the stored path is used by default.

## Security Notes

- The SSH private key itself is **not** stored — only its fingerprint and the HKDF salt
- The fingerprint is checked at derive time to detect if the wrong key is presented
- Passphrase-protected keys are supported; the passphrase is prompted and wiped after use
- If the SSH key is regenerated (even at the same path), the fingerprint will mismatch and derivation will fail — you would need to re-enroll
- The security of this provider is tied to the security of the SSH private key file — if an attacker has your key file (and its passphrase, if any), they can reproduce this provider's secret

## When to Use

The SSH key provider is useful when:

- You already manage SSH keys and want to reuse them as an authentication factor
- You want a file-based provider that doesn't require memorization
- You store SSH keys on hardware tokens (e.g., YubiKey with resident keys) and want a second derivation path

It is **not** a replacement for FIDO2 — the FIDO2 provider uses hardware-bound secrets that cannot be extracted, while SSH keys are files that can be copied.
