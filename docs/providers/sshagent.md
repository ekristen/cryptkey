# SSH Agent Provider

The SSH agent provider derives a 32-byte secret by having the SSH agent sign a deterministic challenge. Only Ed25519 keys are supported.

**Type:** `ssh-agent`

## Requirements

- A running SSH agent with at least one Ed25519 key loaded
- The `SSH_AUTH_SOCK` environment variable must be set

## How It Works

### Enrollment

1. Connects to the SSH agent via `SSH_AUTH_SOCK`
2. Lists Ed25519 keys in the agent (auto-selects if only one)
3. Generates a random 32-byte salt
4. Builds a deterministic challenge: `SHA256(salt || fingerprint || "cryptkey-sshagent-challenge")`
5. The agent signs the challenge with the selected key
6. HKDF derives the secret: `HKDF-SHA256(signature, salt, "cryptkey-sshagent-provider") → 32 bytes`
7. The key's SHA256 fingerprint and salt are stored in the profile
8. The signature is wiped from memory

### Derivation

1. Connects to the SSH agent
2. Finds the enrolled key by its stored fingerprint
3. Rebuilds the same challenge from the stored salt and fingerprint
4. The agent signs the challenge again — Ed25519 signatures are deterministic, so the same signature is produced
5. The same HKDF derivation reproduces the 32-byte secret

## Usage

```bash
# Interactive TUI
cryptkey init
# Select "ssh-agent" from the menu

# Non-interactive
cryptkey init --no-tui \
  --add ssh-agent:yubikey \
  --add passphrase:backup

# Derive — agent must have the key loaded
cryptkey derive
```

## Stored Parameters

| Parameter | Description |
|-----------|-------------|
| `salt` | Hex-encoded 32-byte salt (used in challenge and HKDF) |
| `fingerprint` | SSH SHA256 fingerprint (e.g., `SHA256:abc123...`) |

No file path is stored — the key is identified by fingerprint in the agent.

## Why Ed25519 Only

This provider relies on **deterministic signatures**: signing the same message with the same key must always produce the same signature. Ed25519 has this property by design.

ECDSA signatures include a random nonce, so different signatures are produced each time — the derived secret would change and key reconstruction would fail. While RFC 6979 defines deterministic ECDSA, not all SSH agent implementations guarantee this.

## Security Notes

- The private key **never leaves the agent** — only the signature is used
- No key material is stored in the profile, only the fingerprint and HKDF salt
- The challenge is bound to the specific enrollment via the salt, so the signature cannot be replayed across profiles
- Works with hardware-backed keys (YubiKey, smart cards) where the key cannot be extracted
- The security depends on the agent and key storage — a YubiKey-backed key in the agent is stronger than a software key

## When to Use

The SSH agent provider is ideal when:

- Your SSH key lives on a hardware token (YubiKey, smart card) and is only accessible through the agent
- You use an agent that manages keys for you (1Password SSH agent, Secretive on macOS)
- You don't want the private key file to be read directly
- You want a provider that works without any files on disk

## SSH Agent vs SSH Key Provider

| | `ssh-agent` | `sshkey` |
|---|---|---|
| **Key access** | Agent signs on behalf | Reads private key file directly |
| **Key types** | Ed25519 only | Ed25519, ECDSA, RSA |
| **Hardware keys** | Full support (YubiKey, etc.) | Only if key file is on disk |
| **File on disk** | Not needed | Required |
| **How secret is derived** | From agent's signature | From private key bytes |
| **Agent required** | Yes | No |
