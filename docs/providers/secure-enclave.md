# Secure Enclave Provider

!!! warning "Not Currently Supported"
    The Secure Enclave provider is not supported at this time. macOS requires a provisioning profile to access the data protection keychain used by the Secure Enclave, and provisioning profiles can only be embedded in app bundles — not bare command-line binaries. Since cryptkey is distributed as a standalone CLI tool, it cannot claim the `keychain-access-groups` entitlement needed for Secure Enclave access, even though the binary is signed and notarized for Gatekeeper.

    Wrapping the binary in a `.app` bundle structure may be explored in the future.

**Type:** `secure-enclave`

## How It Would Work

The Secure Enclave provider derives a 32-byte secret using ECDH key agreement with a P-256 key stored in the macOS Secure Enclave. During enrollment, a new hardware-bound key is created and an ECDH exchange with a random ephemeral peer key produces a shared secret. Only the peer public key is stored in the profile; the Secure Enclave private key never leaves the hardware.

## Why It's Blocked

Apple's data protection keychain (`kSecUseDataProtectionKeychain`) requires entitlements authorized by a provisioning profile. A bare Mach-O binary has no place to store a provisioning profile — only app bundles (`.app` directory structures) can embed one at `Contents/embedded.provisionprofile`. Without the provisioning profile, keychain operations return `errSecMissingEntitlement`.

This is a platform limitation confirmed by Apple DTS, not a cryptkey design choice.

## Limitations

- **macOS only** — Secure Enclave is an Apple hardware feature
- **Requires app bundle packaging** — bare CLI binaries cannot access the data protection keychain
- **Machine-bound** — the Secure Enclave key cannot be extracted or migrated to another device
- **Build tag** — excluded with `-tags nosecureenclave`
