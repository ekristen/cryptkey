# Passkey Provider

The passkey provider derives a 32-byte secret using the WebAuthn PRF (Pseudo-Random Function) extension via a browser-based flow.

**Type:** `passkey`

## Requirements

- A modern web browser with WebAuthn PRF support (Chrome 116+, Edge 116+, Firefox 135+)
- A passkey-capable authenticator (platform authenticator, security key, or password manager)

This means anything that holds a WebAuthn passkey **and exposes the PRF extension** can hold a share of your cryptkey secret. Not every passkey-capable vault supports PRF — storing passkeys for website login is common, while exposing PRF for arbitrary-secret derivation is newer. Known to work:

- **Platform authenticators**: macOS Touch ID / Face ID (via Keychain, iOS/macOS 18+), Windows Hello, Android biometrics (Android 14+), iCloud Keychain / Google Password Manager passkey sync.
- **Password managers with PRF**: [1Password](https://1password.com/blog/encrypt-data-saved-passkeys), [Bitwarden](https://bitwarden.com/help/login-with-passkeys/), [Dashlane](https://www.dashlane.com/blog/dashlane-phishing-resistance). Other managers store passkeys too (e.g. Proton Pass) but haven't publicly confirmed PRF support at time of writing — test before relying on them.
- **Roaming security keys**: FIDO2 hardware keys (YubiKey, SoloKey, etc.) with discoverable-credential support — same physical device as the `fido2` provider, but enrolled through the passkey/WebAuthn path instead of the raw CTAP2 `hmac-secret` extension.

If you're unsure whether a specific authenticator or manager supports PRF, Corbado's free tester at [webauthn-passkeys-prf-demo.explore.corbado.com](https://webauthn-passkeys-prf-demo.explore.corbado.com/) will tell you in a few clicks before you enroll.

Because the PRF output is bound to a specific passkey credential, the device or vault that *holds* the passkey controls access to that share; cryptkey only ever sees the 32-byte PRF output, never the credential's private key. That lets you, for example, enroll a 1Password passkey as one provider, a macOS Touch ID passkey as a second, and a printed recovery code as a third — each a separate share toward the same profile's threshold.

## How It Works

### Enrollment

1. Cryptkey starts a local HTTP server on localhost (browsers treat localhost as a secure context)
2. A browser window opens to the local enrollment page
3. The user creates a passkey credential via the browser's WebAuthn UI
4. The PRF extension derives a deterministic 32-byte secret from the credential
5. The credential metadata is stored in the profile

### Derivation

1. Cryptkey starts a local HTTP server on localhost
2. A browser window opens to the local authentication page
3. The user authenticates with their passkey
4. The PRF extension reproduces the same 32-byte secret

## Usage

```bash
# Interactive TUI
cryptkey init
# Select "passkey" from the menu

# Non-interactive
cryptkey init --add passkey:browser-1 --add passphrase:backup
```

## Security Notes

- The PRF extension ensures the secret is deterministic and bound to the credential
- CSRF protection via state tokens prevents cross-site request forgery during the browser flow
- The local server only accepts connections from localhost
- Passkeys can be backed up by the platform (iCloud Keychain, Google Password Manager) — this means they survive device loss but also that the platform has access to the credential
- For maximum security, use a hardware-bound passkey (e.g., a YubiKey) which cannot be backed up

## Differences from FIDO2

| | FIDO2 | Passkey |
|---|-------|---------|
| Interface | Direct USB/NFC via `libfido2` | Browser-based WebAuthn |
| Extension | `hmac-secret` | PRF |
| CGO required | Yes | No |
| Browser required | No | Yes |
| Backup possible | No (hardware-bound) | Depends on authenticator |
