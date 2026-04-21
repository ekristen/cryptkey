# cryptkey rekey

Rebuild a profile with a new provider set and/or threshold while preserving the master key — and therefore every key already derived from the profile.

## Usage

```bash
cryptkey rekey [profile] [options]
```

If `profile` is omitted, cryptkey uses `default`.

## When to use it

- A hardware key died, was lost, or was retired and you want to enroll a replacement.
- You added a new device (laptop, security key, phone) and want to give it access to the profile.
- You want to remove a provider you no longer trust or no longer use.
- You want to change the threshold (e.g., 2-of-3 → 3-of-5).

In every case, output keys derived from the profile (age identities, ed25519 keys, AEAD keys you stored elsewhere) **stay the same**. Only the set of providers that can unlock the profile changes.

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--threshold N`, `-t` | New threshold | keep current |
| `--keep TYPE:ID` | Explicit list of providers to keep (repeatable). Default: keep all that aren't `--remove`d. | — |
| `--remove TYPE:ID` | Drop a provider from the new profile (repeatable) | — |
| `--add TYPE:ID`, `-a` | Enroll a new provider (repeatable; `TYPE` alone auto-assigns an ID) | — |
| `--no-tui` | Force plain-line prompts (no colors, no inline editing) | implied when stderr isn't a TTY |
| `--no-backup` | Skip writing `<profile>.toml.bak` before saving | `false` |
| `--fido2-uv MODE` | FIDO2 user verification for newly enrolled providers | provider default |
| `--argon-time N` / `--argon-memory N` / `--argon-threads N` | Argon2id parameters for newly enrolled passphrase / recovery providers | provider defaults |
| `--timeout DURATION` | Override the hardware-provider timeout during the unlock phase (e.g. `60s`, `2m`) | provider-specific, typically 30s |

## Interactive (TUI)

Running `cryptkey rekey [profile]` with no plan-shaping flags (`--keep`, `--remove`, `--add`, `--threshold`) launches a planning TUI:

- Arrow keys to navigate
- `space` to toggle keep / remove on existing providers
- `a` to add a new provider (type only — id is auto-assigned at enroll time)
- `←` / `→` on the **Threshold** row to adjust the new threshold
- `enter` to confirm and run the rekey
- `esc` or `ctrl+c` to cancel without changes

Once you confirm, the TUI exits and the unlock + enroll phases run in the regular terminal so PIN entry, passphrase entry, and FIDO2 device prompts use the same masked-input UX as `cryptkey derive`.

If you pass any of the plan-shaping flags, the TUI is skipped — useful for scripts. `--no-tui` also forces script mode.

## Examples

Replace a dead FIDO2 key with a new one:

```bash
cryptkey rekey personal \
  --remove fido2:yubikey-old \
  --add fido2:yubikey-new
```

Add a recovery code to an existing profile (threshold unchanged):

```bash
cryptkey rekey personal --add recovery:emergency
```

Tighten security from 2-of-3 to 3-of-5 by adding two more devices:

```bash
cryptkey rekey personal \
  --threshold 3 \
  --add fido2:laptop \
  --add fido2:phone
```

## How it works

`rekey` runs in three phases:

1. **Unlock.** This is the normal `cryptkey derive` flow against the existing profile: every provider is walked in profile order, you can skip individual ones with `esc`, and the phase ends when threshold-many shares have been decrypted and the integrity HMAC verifies. **Providers used for unlock aren't filtered by `--keep` / `--remove`** — a provider you're about to remove is still a valid share of the current polynomial, so it can (and often should) participate in unlock.

2. **Fill in missing kept secrets.** The re-split produces a new share value for every kept provider, and each new share has to be encrypted with that provider's secret. If a kept provider wasn't used during the unlock phase (either it came after threshold was met, or you skipped it), `rekey` prompts for it now. Skipping a required kept provider aborts the rekey — you'd have no way to write a valid share for it.

3. **Enroll.** Each `--add` provider runs through its full enrollment flow (FIDO2 touch + create credential, new passphrase, etc.).

4. **Re-split and write.** A fresh Shamir polynomial of degree `(t' - 1)` is generated with K as its constant term. Every provider — kept and added — gets a new share encrypted with its own secret. The integrity HMAC is recomputed. The original profile is copied to `<profile>.toml.bak` (unless `--no-backup`), and the new profile is atomically written via temp-file + rename.

The existing `output_salt` is preserved verbatim, which is why output keys derived from the same `--use` continue to match.

## Interaction count

For a typical "replace one dead key" rekey on a 5-of-3 profile keeping 4 of the original 5 providers (the 5th is the dead one being removed) and adding 1 new provider:

| Phase | Interactions |
|-------|--------------|
| Unlock (until threshold reached) | 3 |
| Fill-in kept providers not used during unlock | 1 |
| Enroll (added providers) | 1 |
| **Total** | **5** |

The exact split between phases 1 and 2 depends on which providers you choose during unlock — if kept providers happen to be what unlocks the profile, the fill-in phase is empty.

## Safety

- The original profile is never modified in place. The new profile is written to a temp file, fsynced, and renamed. A `.bak` of the previous profile is written first by default.
- If unlock or enrollment fails, no write occurs. The original profile is untouched.
- The integrity HMAC is recomputed against the recovered master key, so a tampered profile that somehow survives the unlock phase still won't write a new profile.
- New hardware credentials (FIDO2 / passkey) are created on the device the moment you enroll them. If a later step fails, those credentials remain on the device but unused — same caveat as `init`.

## Recovering from a failed rekey

If the new profile was written but you suspect it's wrong (typo on a passphrase, wrong device picked, etc.), restore the previous one:

```bash
mv ~/.config/cryptkey/myprofile.toml.bak ~/.config/cryptkey/myprofile.toml
```

The backup is a literal copy of the pre-rekey profile, so the original providers continue to unlock it.
