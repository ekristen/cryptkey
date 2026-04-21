# FIDO2 Provider

The FIDO2 provider derives a 32-byte secret from a hardware security key (YubiKey, SoloKey, Nitrokey, etc.) using the `hmac-secret` extension.

**Type:** `fido2`

## Requirements

- A FIDO2-compatible hardware security key with `hmac-secret` support
- `libfido2` installed on the system (`libfido2-dev` on Debian/Ubuntu, `libfido2` on macOS)
- Cryptkey built with CGO enabled (the default)

## How It Works

### Enrollment

1. Cryptkey creates a FIDO2 credential on the hardware key
2. The `hmac-secret` extension produces a deterministic 32-byte secret bound to the credential
3. The credential ID is stored in the profile for later use
4. The secret is used to encrypt the provider's Shamir share

### Derivation

1. Cryptkey reads the stored credential ID from the profile
2. The hardware key is prompted to authenticate (requires physical touch)
3. The `hmac-secret` extension reproduces the same 32-byte secret
4. The secret decrypts the provider's share

## Usage

```bash
# Interactive TUI
cryptkey init
# Select "fido2" from the menu

# Non-interactive
cryptkey init --add fido2:yubikey-1 --add passphrase:backup
```

## Stored Parameters

| Parameter | Description |
|-----------|-------------|
| `credential_id` | Hex-encoded FIDO2 credential ID |
| `rp_id` | Relying party ID used during credential creation |

## Security Notes

- The secret cannot be extracted from the hardware key — it requires physical possession and touch
- Each credential produces a unique secret; different keys produce different secrets
- If the hardware key is lost or destroyed, this provider cannot be used (ensure your threshold can be met without it)
- The credential ID alone is useless without the physical hardware key
