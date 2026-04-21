# Profiles

A **profile** is the single TOML file that stitches your providers, threshold, and encrypted shares together. Everything cryptkey needs to reconstruct your key — except the providers themselves — lives in this file. Losing the profile means losing access even if every provider is still in your possession.

This page covers what's in a profile, what's sensitive and what's not, how to back it up, and how to move or share it between systems.

## Where profiles live

```
Linux / BSD     ~/.config/cryptkey/<name>.toml
macOS           ~/Library/Application Support/cryptkey/<name>.toml
```

The directory is created with mode `0700` (owner-only) and individual profile files with mode `0600`. When cryptkey writes a profile it does so atomically via a temporary file in the same directory + `rename(2)`, so a crash mid-write never leaves a torn file.

`cryptkey list` prints every profile it finds. `cryptkey info <name>` prints a profile's threshold, provider list, and creation metadata without attempting to unlock anything.

## Anatomy of a profile

Here's the shape of a real profile (one passphrase + one recovery code, threshold 2), with irrelevant bytes elided:

```toml
version = 1
name = "default"
threshold = 2
output_salt = "b3c1…a0ef"     # 32 bytes, hex
integrity = "42da…5fff"       # HMAC-SHA256, hex

[[providers]]
  type = "passphrase"
  id = "primary"
  encrypted_share = "9e4a…0122"    # AES-256-GCM ciphertext, hex
  nonce = "7b5c…f301"              # 96-bit GCM nonce, hex
  share_salt = "2d8e…b411"         # 32-byte HKDF salt, hex
  [providers.params]
    argon_memory = "262144"
    argon_threads = "4"
    argon_time = "3"
    salt = "4fa0…7c28"             # 32-byte Argon2id salt, hex

[[providers]]
  type = "recovery"
  id = "paper"
  encrypted_share = "…"
  nonce = "…"
  share_salt = "…"
  [providers.params]
    argon_memory = "262144"
    argon_threads = "4"
    argon_time = "3"
    salt = "…"
```

Each provider block carries three categories of data:

- **Ciphertext** — `encrypted_share` and its `nonce`.
- **KDF inputs** — `share_salt`, plus provider-specific params (e.g. Argon2 salt, FIDO2 credential ID, SSH key path).
- **Integrity binding** — the top-level `integrity` HMAC covers every field above, keyed by the master key, so tampering flips the verification.

## What IS sensitive — and isn't in the profile

The master key, the plaintext Shamir shares, and every provider secret (passphrase bytes, FIDO2 `hmac-secret` output, SSH private key material, recovery-code bytes) are **never** written to the profile. They live in RAM for the duration of `cryptkey init` / `cryptkey derive` / `cryptkey rekey` and are explicitly zeroed before those commands return.

If every copy of the profile were stolen tomorrow, the thief could not reconstruct your key without also defeating enough of your providers to meet the threshold. That's the whole point of Shamir + per-share encryption.

## What's in the profile — and what a thief can do with it

A profile is best thought of as **low-sensitivity metadata plus ciphertext**. It's not secret the way a private key is secret, but it isn't something you'd publish on a status page either.

| Field | Category | A thief can… |
|---|---|---|
| `version`, `name`, `threshold` | Metadata | See which providers you enrolled and how many are needed. Enumeration value: low. |
| `output_salt` | Public KDF input | Nothing by itself. Feeds the final HKDF so every profile's derived output keys are domain-separated even if two profiles somehow ended up with the same master key; survives `rekey` so derived age / ed25519 / AEAD keys stay stable across provider rotation. |
| `integrity` | Public MAC tag | Detect tampering; can't forge without the master key. The HMAC is what stops an attacker with profile write access from rewriting fields outside the ciphertext (`threshold`, `output_salt`, provider ordering) to silently redirect your output keys. See [Integrity Verification](security.md#integrity-verification) for the attack it defends against. |
| `encrypted_share` | Ciphertext | Try offline attacks against the provider that decrypts it. For passphrase/recovery providers, this is an Argon2id brute-force window — security depends entirely on the passphrase strength and the Argon2 parameters in the profile. For FIDO2 / PIV / TPM / ssh-agent / ssh-key, offline attacks are not feasible without the hardware or key file. |
| `nonce`, `share_salt` | Public KDF inputs | Nothing by themselves. |
| `params.*` | Provider metadata | See provider config (FIDO2 credential IDs, SSH key paths, Argon2 costs). For FIDO2, the credential ID alone cannot prompt your key to sign; the `hmac-secret` extension still requires physical presence. For SSH key, the path tells them which key file to look for if they're also on your host. |

### The concrete threat: weak passphrases

The one realistic attack against a leaked profile is an **offline dictionary attack on passphrase and recovery-code providers**. Cryptkey stretches those through Argon2id at the memory/time costs stored in the profile (defaults: `t=3`, `m=256 MiB`, `p=4`), so a rented GPU is going to cost real money per guess — but a six-character passphrase is still recoverable at that cost.

Mitigations:

1. **Use strong passphrases.** A memorable 4+ word passphrase (diceware style) easily outruns any practical brute force.
2. **Keep the Argon2 parameters high.** The defaults are reasonable; if you run on beefy hardware, you can raise `--argon-memory` and `--argon-time` on `init` / `rekey`.
3. **Keep at least one hardware or recovery-code provider in your threshold.** If your threshold requires combining a passphrase with, say, a FIDO2 key, the profile ciphertext cannot be cracked by brute-forcing the passphrase alone — a threshold of valid secrets is required to produce the master key that validates the integrity HMAC.

For profiles made entirely of passphrase or recovery-code providers, treat the profile the same way you'd treat the passphrases themselves — as a shared-fate secret.

## Backups

**You must back up your profile.** This is the single biggest "way to lock yourself out" with cryptkey: the providers themselves (FIDO2 keys, ssh keys, TPM, passkeys) have no knowledge of your profile, so without it they cannot reconstruct the key. Profile lost = keys lost, full stop.

Good backup practice:

- **Make at least two copies, on independent media.** A USB stick in a drawer + a copy synced to cloud storage is a reasonable floor. Three copies across three failure domains (local drive, offsite drive, online) is better.
- **Cloud sync is fine.** Profiles are encrypted ciphertext plus low-value metadata. You can drop `~/.config/cryptkey/` into Dropbox / iCloud / Syncthing without weakening the threat model — the cloud host has the same thing an offline thief would have.
- **Version the backups.** If you `rekey`, the pre-rekey `.toml.bak` (automatic unless `--no-backup`) is itself a valid profile for the old provider set. Keep it around until you're sure every provider in the new set works.
- **Don't skip the backup for a single-provider profile.** A 1-of-1 profile (one passphrase, no redundancy) is the *most* at risk from profile loss — no other provider can unlock it.

A concrete example, mirroring a profile into a git repo + age-encrypted vault:

```bash
# One-off: stage a backup directory on a mount of your choice.
mkdir -p ~/Backups/cryptkey
chmod 700 ~/Backups/cryptkey

# Copy profiles into the backup dir.
rsync -a ~/.config/cryptkey/ ~/Backups/cryptkey/

# Optional: belt-and-suspenders, age-encrypt the whole dir with a different
# recipient so even the low-sensitivity metadata stays private.
tar cf - -C ~/.config cryptkey \
  | age -r age1... -o ~/Backups/cryptkey-$(date +%F).tar.age
```

The second step is paranoia, not necessity: the cryptkey profile is already ciphertext. Do it if you want the provider list itself to stay private (e.g. "this machine has a FIDO2 credential" is information you'd rather not leak).

### Do NOT back up your providers the same way

The profile is the piece to back up in multiple places. The providers themselves have their own backup story and should not be lumped in:

- **Passphrases / recovery codes** — memorize or store in a password manager. Printing the recovery code and sealing it in an envelope is traditional for a reason.
- **FIDO2 / PIV hardware keys** — enroll *multiple physical devices* as separate providers, rather than trying to "back up" one device. A YubiKey cannot be cloned safely; a second YubiKey enrolled alongside it is the correct redundancy pattern.
- **SSH keys** — the key file already has its own backup story (usually: it doesn't; you regenerate if lost). Enroll a second SSH key as a separate provider rather than copying `id_ed25519` around.
- **Passkeys** — platform-managed, synced by the vendor (Apple iCloud Keychain, Google Password Manager, etc.). Their backup story is the vendor's.

## Moving a profile to a new system

Copying the profile is necessary but may not be sufficient — whether the same providers still work depends on the provider type:

| Provider | Works after copying the profile? |
|---|---|
| passphrase / recovery | Yes — portable. |
| FIDO2 | Yes, if the same physical key is plugged in. FIDO2 credentials are per-device. |
| PIV / YubiKey-PIV | Yes, if the same smartcard is present. Credentials live on the card. |
| passkey | Usually yes — passkeys are synced by the platform. Occasionally a specific site-bound passkey won't roam. |
| ssh-key | Yes, if the key file exists at the same path (or a path you re-specify). |
| ssh-agent | Yes, if the same key is loaded in the ssh agent on the new machine. |
| tpm | **No.** TPM providers are bound to the specific TPM chip that enrolled them. Cannot be migrated. |
| secure-enclave | Not supported (see [Providers → Secure Enclave](providers/secure-enclave.md)). |

So for a TPM provider specifically, copying the profile to another machine produces a profile where that provider slot is dead. If TPM was critical to meeting the threshold, you'll have to `cryptkey rekey` on the original machine to replace it with a portable provider before migrating.

### Recommended flow for a clean migration

1. On the old machine: `cp ~/.config/cryptkey/<name>.toml` to whatever transport you want (encrypted USB, cloud, age-encrypted file, …).
2. On the new machine: copy it into `~/.config/cryptkey/` with `chmod 600`.
3. Run `cryptkey info <name>` — it reads the profile without unlocking, so you can sanity-check the provider list on the new host.
4. Run `cryptkey derive <name>` — the real test. You should be able to authenticate with the threshold of providers that are actually present on the new host.
5. If a provider is dead on the new host (missing hardware, TPM-bound), run `cryptkey rekey <name> --remove <type>:<id> --add <replacement>` to fix it up.

## Deleting a profile

`rm ~/.config/cryptkey/<name>.toml` is sufficient functionally. If you're particularly cautious about the provider list leaking from recovered disk sectors, `shred -u` is a reasonable extra step on mechanical disks — it's mostly theatre on SSDs (the firmware is in charge of block reuse), where a full-device secure-erase is the only rigorous answer.

There is no plaintext key material in the profile to "leak out of" the deleted file, so the usual concerns around deleting key files don't really apply here. What leaves evidence behind is the provider list and parameter set (Argon2 costs, FIDO2 RP IDs, etc.) — which is closer to "metadata about what the user was doing" than "secret material."
