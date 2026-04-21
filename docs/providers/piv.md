# PIV Provider

The PIV provider derives a 32-byte secret from a PIV-compatible smart card (YubiKey, etc.) by performing ECDH between an on-device ECDSA P-256 key and a peer key derived deterministically from a random salt, then feeding the shared point through HKDF-SHA256.

**Type:** `piv`

## Requirements

- A PIV-compatible smart card (YubiKey 4/5) with an ECDH-capable slot
- PC/SC subsystem installed and running
    - Linux: `pcscd` + `libpcsclite` (`pcscd` + `libpcsclite-dev` on Debian/Ubuntu)
    - macOS: built-in via CryptoTokenKit
- The chosen slot must support `KEY_MANAGEMENT_DECIPHER` (ECDH). This rules out slot `9c` (signature-only). Default slot `9d` is designed for key agreement.

## How It Works

ECDH is used (not ECDSA signing) because scalar multiplication is inherently deterministic — there is no nonce. YubiKey firmware 5.7+ uses random nonces for ECDSA signing as a side-channel mitigation, so a signing-based scheme would produce different bytes on every call and make the secret unrecoverable.

### Enrollment

1. Cryptkey connects to the card via PC/SC and (unless one exists already) generates an ECDSA P-256 key in the chosen slot.
2. A random 32-byte salt is generated and expanded via HKDF into a P-256 scalar `s`; the peer public key is `s · G`.
3. The card performs ECDH: `shared = slot_priv · peer_pub`. Cryptkey verifies the result locally by computing `s · slot_pub` and comparing the x-coordinate — this confirms the card is producing the expected output before the secret is committed.
4. `shared` is fed to HKDF-SHA256 with the salt to produce the 32-byte provider secret. Salt, slot, serial, slot public key, and card name are stored in the profile.

### Derivation

1. Cryptkey enumerates PIV cards, matches by stored serial, and loads the slot public key from the profile.
2. The peer public key is re-derived deterministically from the salt.
3. The card performs ECDH with the peer public key; HKDF-SHA256 reproduces the 32-byte secret.

## Usage

```bash
# Interactive TUI
cryptkey init
# Select "piv" from the menu

# Non-interactive
cryptkey init --add piv:yubikey-piv --add passphrase:backup
```

## Stored Parameters

| Parameter      | Description |
|----------------|-------------|
| `salt`         | 32-byte hex salt mixed into the challenge and HKDF |
| `slot`         | Hex PIV slot identifier (e.g. `9d`) |
| `serial`       | Card serial number for matching during derive |
| `public_key`   | Uncompressed P-256 point for the slot's key |
| `card_name`    | PC/SC reader name (informational) |
| `touch_policy` | `never`, `always`, or `cached` |

## Enrollment Options

| Option         | Values | Default | Purpose |
|----------------|--------|---------|---------|
| `slot`         | `9d`, `9a`, `9c`, `9e`, `82`–`85` | `9d` | Which PIV slot holds the key |
| `touch_policy` | `never`, `always`, `cached` | `never` | Whether physical touch is required for each ECDH key-agreement operation |
| `mode`         | `use-existing`, `overwrite` | `use-existing` | How to handle a slot that already contains key material |

### `mode` behavior

- **`use-existing`** — if the slot already has an on-device ECDSA P-256 key, reuse it and skip straight to the PIN prompt (and touch, if required). If the slot is empty, a new key is generated. This is the safest default and is what you want when re-enrolling a card you've already used with cryptkey.
- **`overwrite`** — always generate a fresh key. If the slot is already in use, cryptkey requires an explicit typed confirmation (`confirm overwrite` in the TUI, or the same phrase on `/dev/tty` in `--no-tui` mode) before destroying the existing key. Any certificates or services bound to that slot will stop working.

## Slot Choice

| Slot | Purpose | Notes |
|------|---------|-------|
| `9d` | Key Management | **Recommended** — designed for ECDH/key agreement |
| `9a` | Authentication | Commonly used for SSH/PIV login; collides with other tools |
| `9e` | Card Authentication | Low-security, sometimes PIN-less |
| `82`–`85` | Retired slots | Available for general use |

Slot `9c` is deliberately omitted because it is signature-only and cannot perform ECDH.

## Security Notes

- The private key never leaves the device; the secret is hardware-bound.
- The PIN is cached for the session by `PINPolicy=Once`. Losing the card means losing this share — keep your threshold recoverable without it.
- A factory-provisioned certificate in a slot is ignored; cryptkey uses on-device attestation to decide whether the slot contains real user key material.

---

## Linux Setup: PC/SC Access (polkit)

On modern Linux distributions, `pcscd` uses **polkit** to authorize clients. By default, non-root processes are often denied access and will see errors like:

```
piv: detect cards: connecting to pcsc: access was denied because of a security violation
```

and `journalctl -u pcscd` will show:

```
auth.c:143:IsClientAuthorized() Process NNNN (user: 1000) is NOT authorized for action: access_pcsc
winscard_svc.c:355:ContextThread() Rejected unauthorized PC/SC client
```

### Recommended: grant access to a group

Create a dedicated group (or reuse `plugdev`), add your user to it, and grant the group PC/SC access via a polkit rule. Groups are the cleanest way to scope access on shared systems.

```bash
# Create the group and add yourself
sudo groupadd -f pcscd
sudo usermod -aG pcscd "$USER"

# Log out and back in (or run: newgrp pcscd) so the membership takes effect
```

Then write `/etc/polkit-1/rules.d/99-pcscd.rules`:

```javascript
polkit.addRule(function(action, subject) {
    if ((action.id == "org.debian.pcsc-lite.access_pcsc" ||
         action.id == "org.debian.pcsc-lite.access_card") &&
        subject.isInGroup("pcscd")) {
        return polkit.Result.YES;
    }
});
```

Reload polkit and verify:

```bash
sudo systemctl restart polkit
pkaction --verbose --action-id org.debian.pcsc-lite.access_pcsc
journalctl -u polkit -n 20 --no-pager   # check for JS syntax errors
```

### Alternative: grant access to a single user

If you don't want a group, gate the rule on `subject.user` instead:

```javascript
polkit.addRule(function(action, subject) {
    if ((action.id == "org.debian.pcsc-lite.access_pcsc" ||
         action.id == "org.debian.pcsc-lite.access_card") &&
        subject.user == "alice") {
        return polkit.Result.YES;
    }
});
```

### Notes

- Rule files must be owned by root, mode 0644, and syntactically valid JavaScript. Syntax errors are silently ignored — check `journalctl -u polkit` after editing.
- The `99-` prefix ensures the rule runs after any distribution defaults.
- Avoid a blanket `return polkit.Result.YES` with no subject check — that grants PC/SC access to every user and service on the system, including unprivileged daemons.

## Troubleshooting

### `smart card reader is in use — gpg-agent's scdaemon is holding the device`

gpg-agent's scdaemon claims the CCID interface exclusively. Kill it and configure gpg to stop using the built-in CCID driver:

```bash
gpgconf --kill scdaemon
echo "disable-ccid" >> ~/.gnupg/scdaemon.conf
```

### `smart card reader is in use — gpg-agent is running and may be holding the CCID interface`

On systems where gpg-agent is systemd-supervised (`--supervised`), a plain `pkill` won't stick — systemd respawns it via socket activation. Stop the sockets first:

```bash
systemctl --user stop gpg-agent.service \
    gpg-agent.socket gpg-agent-ssh.socket \
    gpg-agent-extra.socket gpg-agent-browser.socket
```

To prevent it from starting at all: `systemctl --user mask` those same sockets.

### `ECDH failed (slot X may not support KEY_MANAGEMENT_DECIPHER)`

The chosen slot cannot perform ECDH. Slot `9c` is signature-only; re-run with slot `9d` (the default, designed for key agreement) or one of the retired slots (`82`–`85`).

### `card ECDH output does not match expected value`

The card returned an ECDH result that didn't match what cryptkey computed locally. This is either hardware corruption, a counterfeit device, or a cryptkey bug — please open an issue with the card model and firmware version (`ykman info`).
