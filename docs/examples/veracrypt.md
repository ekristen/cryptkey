# VeraCrypt

[VeraCrypt](https://veracrypt.fr/) creates encrypted containers and volumes. It supports keyfiles and passwords-from-stdin, both of which integrate cleanly with cryptkey — without writing the derived key to a temporary file.

!!! note
    VeraCrypt requires root privileges for device-mapper operations, so every command below involves `sudo`. The order in which cryptkey and sudo run matters — see [Sequencing sudo and cryptkey](#sequencing-sudo-and-cryptkey) below if you see sudo prompt before your cryptkey prompts finish.

## Preferred: let cryptkey exec sudo

Instead of piping through the shell, tell `cryptkey derive` to run `sudo veracrypt` itself with `-- ...`. That way cryptkey completes its provider prompts first, then execs the child — so sudo's password prompt has unobstructed access to `/dev/tty`:

```bash
# Mount (keyfile mode — fast, skips VeraCrypt's own stretching)
cryptkey derive --raw -- sudo veracrypt -t \
  --keyfiles=/dev/stdin \
  --password="" --pim=0 --non-interactive \
  /path/to/container.vc /mnt/encrypted

# Mount (password mode — portable, slightly slower)
cryptkey derive -- sudo veracrypt -t \
  --pim=0 --non-interactive --stdin \
  /path/to/container.vc /mnt/encrypted
```

When cryptkey execs `sudo`, it pipes its own output into sudo's stdin. sudo passes stdin through to veracrypt, so veracrypt receives the hex key (`--stdin` mode) or raw key (`/dev/stdin` keyfile mode). The cryptkey provider prompts run on `/dev/tty`, then cryptkey exits the prompt phase, then sudo prompts for its password — no overlap.

The exact same pattern works for creating a volume:

```bash
cryptkey derive --raw -- sudo veracrypt -t -c \
  --volume-type=normal \
  --size=1G \
  --encryption=aes \
  --hash=sha-512 \
  --filesystem=ext4 \
  --keyfiles=/dev/stdin \
  --password="" \
  --pim=0 \
  --non-interactive \
  --random-source=/dev/urandom \
  /path/to/container.vc
```

## Why not just pipe?

A plain shell pipe:

```bash
cryptkey derive --raw | sudo veracrypt ...   # fights over /dev/tty
```

starts both processes simultaneously. cryptkey wants `/dev/tty` for its provider prompts; sudo wants `/dev/tty` for its password prompt; they race and you'll often see sudo prompt before the provider flow even finishes. The `cryptkey derive --raw -- sudo ...` form sequences them cleanly.

## Sequencing sudo and cryptkey

If for some reason you still want to use a shell pipe, pre-cache sudo credentials first:

```bash
# Prompt for the sudo password once, then run the pipe.
sudo -v && cryptkey derive --raw | sudo veracrypt -t \
  --keyfiles=/dev/stdin --password="" --pim=0 --non-interactive \
  /path/to/container.vc /mnt/encrypted
```

`sudo -v` validates (and caches) sudo credentials, so the subsequent `sudo veracrypt` runs non-interactively. cryptkey then owns `/dev/tty` for provider prompts without contention.

For fully unattended mounts, give the operating user `NOPASSWD` on veracrypt in `/etc/sudoers.d/`:

```
yourusername ALL=(root) NOPASSWD: /usr/bin/veracrypt
```

## Alternative: process substitution (multiple keyfiles)

Bash's process substitution (`<(command)`) hands a consumer a `/dev/fd/N` path that represents a running command's output. For a *single* keyfile, `--keyfiles=/dev/stdin` already does the same thing without the caveats below, so there's no reason to reach for `<(...)`.

The legitimate win is **mixing multiple keyfiles where some come from cryptkey and others don't**. VeraCrypt's `--keyfiles` accepts a comma-separated list, and stdin can only be one thing. Process substitution lets you compose several independent sources in one invocation:

```bash
# Derive a cryptkey keyfile AND combine it with a physical keyfile on a
# USB stick — both must be present to mount. The two <() expansions give
# veracrypt two separate /dev/fd/N paths at once; /dev/stdin can't.
sudo --preserve-fd=63,64 veracrypt -t \
  --keyfiles="<(cryptkey derive --raw --use vault-main),/media/usb/keyfile.bin" \
  --password="" --pim=0 --non-interactive \
  /path/to/container.vc /mnt/encrypted

# Or two separate cryptkey-derived keyfiles from different --use labels,
# so each keyfile comes from a domain-separated HKDF output:
sudo --preserve-fd=63,64 veracrypt -t \
  --keyfiles="<(cryptkey derive --raw --use a),<(cryptkey derive --raw --use b)" \
  --password="" --pim=0 --non-interactive \
  /path/to/container.vc /mnt/encrypted
```

Two caveats to know:

- **FD allocation is dynamic.** `<(...)` picks the FD number at runtime (usually 63 on bash, 10+ on zsh), and `sudo` closes file descriptors >2 by default. You have to tell sudo which ones to preserve with `--preserve-fd=63,64,...`; if the shell picks different numbers the flag has to match. Bash expands one `<()` per FD, so each needs its own entry in the list.
- **Each `<(cryptkey derive ...)` is a separate authentication flow.** Two process substitutions mean two provider unlocks in parallel, which is usually not what you want — cryptkey will race for `/dev/tty` between the two invocations. For *mixed* sources (one `<(cryptkey derive ...)` plus a regular file path on disk), this isn't an issue and is the natural use case.

If you just want one keyfile, use `--keyfiles=/dev/stdin` with the `cryptkey derive -- sudo ...` pattern shown above. The process-substitution form earns its complexity only when you have genuinely independent keyfile sources to compose.

## Shell helpers

```bash
vc-mount() {
    local container="$1"
    local mountpoint="${2:-/mnt/encrypted}"
    cryptkey derive --raw -- sudo veracrypt -t \
        --keyfiles=/dev/stdin --password="" --pim=0 --non-interactive \
        "$container" "$mountpoint"
}

vc-umount() {
    sudo veracrypt -t -u "${1:-/mnt/encrypted}"
}
```

Pass a named profile when you keep multiple vaults: `cryptkey derive work --raw -- sudo veracrypt ...`.

## Notes

- The keyfile approach (`--password="" --keyfiles=/dev/stdin`) is preferred over `--stdin` for mount speed because it avoids VeraCrypt's internal password hashing on an already-derived key.
- VeraCrypt supports multiple keyfiles — you could combine a cryptkey-derived keyfile with a user-provided one for extra defense.
- VeraCrypt containers can be safely stored on cloud storage or external drives.
- Use `--use` for per-container domain separation: `cryptkey derive --raw --use photos -- sudo veracrypt ...`, `cryptkey derive --raw --use backups -- sudo veracrypt ...`. Different containers, same cryptkey profile, independent keys.
