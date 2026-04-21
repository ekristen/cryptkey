# LUKS

[LUKS](https://gitlab.com/cryptsetup/cryptsetup) (Linux Unified Key Setup) is the standard for Linux disk encryption. cryptsetup accepts keyfiles or passphrases on stdin, both of which cryptkey can drive directly — no temp files, no process-substitution gymnastics.

!!! note
    cryptsetup operations require root, so every command below goes through `sudo`. The `cryptkey derive --raw -- sudo …` pattern sequences cryptkey's provider prompts ahead of sudo's password prompt so they don't race for `/dev/tty`. The [VeraCrypt example](veracrypt.md#why-not-just-pipe) goes into more depth on why that matters.

## Preferred: keyfile on stdin

cryptsetup reads a keyfile from stdin when `--key-file -` is passed. cryptkey's `-- <cmd>` exec sends the derived key to the child's stdin, so the pair composes cleanly:

```bash
# Format a new volume
cryptkey derive --raw -- sudo cryptsetup luksFormat /dev/sdX --key-file -

# Open it
cryptkey derive --raw -- sudo cryptsetup luksOpen /dev/sdX encrypted --key-file -

# Close when done
sudo cryptsetup luksClose encrypted
```

The key flows through the pipe in memory only — no `/tmp`, no `/dev/shm`, no `shred` step.

### Mount and unmount

```bash
sudo mount /dev/mapper/encrypted /mnt/encrypted
# ... use the filesystem ...
sudo umount /mnt/encrypted
sudo cryptsetup luksClose encrypted
```

## Passphrase-style invocation

cryptsetup's stdin reader treats the bytes as a passphrase by default, so you can also pipe the hex-encoded output (no `--raw`):

```bash
cryptkey derive -- sudo cryptsetup luksFormat /dev/sdX
cryptkey derive -- sudo cryptsetup luksOpen /dev/sdX encrypted
```

This still invokes LUKS's PBKDF2/Argon2 stretching on the hex string — slightly slower on open than the raw-keyfile form but equivalent in security.

## Unlock helper

```bash
#!/bin/bash
# unlock.sh — open an encrypted volume using cryptkey.
set -euo pipefail

DEVICE="/dev/sdX"
MAPPER_NAME="encrypted"
MOUNT_POINT="/mnt/encrypted"

cryptkey derive --raw -- sudo cryptsetup luksOpen \
    "$DEVICE" "$MAPPER_NAME" --key-file -
sudo mount "/dev/mapper/$MAPPER_NAME" "$MOUNT_POINT"

echo "Mounted at $MOUNT_POINT"
```

No temp file, no trap, no cleanup step — the key never leaves cryptkey's memory and the pipe buffer.

## Multiple key slots

LUKS volumes have up to 8 key slots; you can add independent keys with `luksAddKey`. Two useful patterns:

### Different `--use` label on the same profile

```bash
# Slot 0 was created with the default-use key above; add a second slot
# keyed by a different --use label on the same cryptkey profile.
cryptkey derive --raw -- sudo cryptsetup luksAddKey /dev/sdX \
    --key-file <(cryptkey derive --raw --use luks-backup)
```

The outer `cryptkey derive --raw -- sudo …` provides the *existing* key that authenticates `luksAddKey` (cryptsetup reads stdin for that). The `<(cryptkey derive --raw --use luks-backup)` process substitution provides the *new* key to add. Two independent HKDF outputs, one profile, one auth flow per derive. (See the [VeraCrypt process-substitution notes](veracrypt.md#alternative-process-substitution-multiple-keyfiles) for why `<()` works here with `sudo` — same caveats apply.)

### A separate profile for the backup slot

When you want the backup slot to be unlockable by a different set of providers entirely, enroll a second profile with its own provider set, then compose:

```bash
cryptkey init luks-backup --add fido2:backup-yubikey --add recovery:paper
# ...later, add its key to the LUKS volume:
cryptkey derive --raw -- sudo cryptsetup luksAddKey /dev/sdX \
    --key-file <(cryptkey derive luks-backup --raw)
```

## Notes

- LUKS runs its own key stretching (PBKDF2 on LUKS1, Argon2id on LUKS2) over whatever you feed `--key-file`. The keyfile can be any length; **what matters is entropy, not byte count**. cryptkey's 32 bytes of output are 256 bits of entropy — plenty for any LUKS cipher.
- `--key-size 512` (if you set it) refers to the cipher's internal key material (AES-XTS uses two 256-bit keys = 512 bits), not the keyfile length. Pass it to `luksFormat` only if you want to override the cipher default; leave it off for default behavior.
- LUKS2 is the default on modern distros and uses Argon2id for its KDF by default.
- Your LUKS header (containing the encrypted volume key plus the hashed keyfile slots) lives on the disk itself; cryptkey's profile doesn't need to back it up, but a `cryptsetup luksHeaderBackup` of the LUKS header is still worth doing — profile loss and LUKS-header loss are separate failure modes.
