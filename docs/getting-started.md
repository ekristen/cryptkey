# Getting Started

## Installation

### Recommended: Distillery

[Distillery](https://dist.sh) is a small installer that fetches the right prebuilt binary for your platform from cryptkey's GitHub releases and drops it in your `$PATH`. No Go toolchain, no `libfido2-dev`, no compilation — the release binaries are fully static so they run on any recent Linux or macOS out of the box.

```bash
# Install distillery if you don't already have it — see https://dist.sh for the latest bootstrap.
# Then install cryptkey:
dist install ekristen/cryptkey
```

Upgrades are a `dist install ekristen/cryptkey` away; distillery tracks the latest release tag.

### Alternative: Prebuilt binaries from GitHub Releases

If you prefer to grab binaries manually, each release at [github.com/ekristen/cryptkey/releases](https://github.com/ekristen/cryptkey/releases) ships a portable static build for Linux and macOS. Download the one for your platform, `chmod +x`, and move it into a directory on your `$PATH`.

### From source

Only needed if you want to build from a specific commit or hack on the code. The release binaries are statically linked and do not require you to have `libfido2` / `libcbor` / `libcrypto` / `libpcsclite` installed at runtime, so source builds are not the expected path for end users.

```bash
# Ubuntu/Debian — install FIDO2 development library for the dev (dynamic) build
sudo apt install libfido2-dev

# macOS
brew install libfido2

# Install the latest tagged release with Go
go install github.com/ekristen/cryptkey@latest
```

For reproducing the release artifacts locally (fully static binary, same as CI), see [Static Builds](development/static-builds.md).

## Quick Start (No Hardware Required)

The fastest way to try cryptkey — create a profile with two passphrases and a recovery code, threshold 2 (the default):

```bash
# Create the "default" profile with three providers, threshold 2 —
# any two of the three unlock the key, so losing one is survivable.
# Omitting the profile name uses "default".
cryptkey init \
  --add passphrase \
  --add passphrase \
  --add recovery

# cryptkey prompts you to enter and confirm each passphrase, and
# prints the recovery code ONCE at enrollment — write it down.

# Derive the key — authenticate with any two of the three providers
cryptkey derive

# Pass the key to another command
cryptkey derive --raw -- my-tool --key-file /dev/stdin
```

`--add passphrase` without an `:id` suffix auto-numbers to `passphrase-1`, `passphrase-2`; `--add recovery` generates a single-use printable code and the recovery provider's ID is `recovery-1`. Any two of the three unlock the profile, which is what the default threshold of 2 buys you — a config with no redundancy (two providers, threshold 2) would require *both* every time, which defeats the point.

This flow needs no hardware keys, browser, or SSH key. The `default` profile is a good place to start; give a profile a specific name (e.g. `cryptkey init work`) when you want more than one. See [Threshold Planning](security.md#threshold-planning) for picking the right ratio.

## Creating Your First Profile

A profile defines which providers protect your key and how many are needed to unlock it (the threshold).

### Interactive Mode (TUI)

```bash
cryptkey init
```

This launches an interactive terminal UI where you can:

- Select providers from a menu
- Enter IDs and passphrases
- See enrolled providers as you go
- Press `d` when you've enrolled enough providers

### Flag-Driven Mode

`--add <type>` declares a provider up front; with enough of them the provider-selection TUI is skipped entirely. You're still prompted per provider for the things only you can supply (passphrase entry, SSH key path, FIDO2 touch, etc.) — the flags just tell cryptkey *which* providers to enroll and in what order.

```bash
cryptkey init \
  --add passphrase \
  --add recovery \
  --add sshkey
```

Three providers with threshold 2 (the default) — any two unlock. Auto-numbered IDs (`passphrase-1`, `recovery-1`, `sshkey-1`) are assigned when you omit the `:id` suffix; pass `--add passphrase:work` if you want a specific name.

!!! note "The `:id` part is a label, not a path"
    `--add passphrase:work` gives the passphrase provider the ID `work`. `--add sshkey:~/.ssh/id_ed25519` would set the ID to the literal string `~/.ssh/id_ed25519` — **it does not tell cryptkey which key file to use**. The key file path is collected interactively at enrollment time.

### Naming your profile (optional)

Omitting the name writes to the **`default`** profile. Every cryptkey command falls back to `default` when no name is given, so one profile per user with no extra typing is the intended common case.

If you want more than one profile (a work vault plus a personal vault, say, or one profile per project), pass a name:

```bash
cryptkey init work \
  --add fido2 \
  --add passphrase \
  --add recovery
```

**The name you use at `init` has to be repeated at every subsequent cryptkey command for that profile.** `cryptkey derive` without a name derives from `default`, not from `work` — so you need `cryptkey derive work`, `cryptkey info work`, `cryptkey rekey work`, etc. Stick with the default when you can; reach for named profiles only when you genuinely need the separation.

## Choosing a Threshold

The threshold is the minimum number of providers needed to reconstruct your key. With 3 providers and a threshold of 2:

- Any 2 of your 3 providers can unlock the key
- Losing 1 provider doesn't lock you out
- An attacker needs to compromise 2 providers

!!! tip "Rule of thumb"
    Set the threshold to `ceil(n/2)` where `n` is the total number of providers. This balances security against availability.

!!! warning "Recovery planning"
    Make sure you have enough non-hardware providers (passphrases, recovery codes) to meet the threshold. If all your hardware is lost or destroyed, you need another way in. Cryptkey warns you during enrollment if this isn't the case.

## Deriving Your Key

Once a profile is created, derive the key by authenticating with enough providers:

```bash
# Print to stdout as hex (default; reads the default profile)
cryptkey derive

# Base64 encoding
cryptkey derive --base64

# Raw bytes (for piping to tools that need binary key material)
cryptkey derive --raw

# Named profile — same command plus the name you chose at init
cryptkey derive work
```

The derived key is always 32 bytes (256 bits) — the standard size for symmetric cryptography.

## Passing Keys to Other Tools

The `derive` command can pass the key directly to a child process. By default it goes on stdin; use `--env` to set an environment variable instead (but see the caveat at the bottom):

```bash
# Pass raw bytes on stdin to a child process (preferred)
cryptkey derive --raw -- cryptsetup open /dev/sda1 vault --key-file=-

# Set SECRET_KEY env var and run my-tool
cryptkey derive --env SECRET_KEY -- my-tool serve
```

!!! tip "Prefer stdin over `--env`"
    Stdin delivery passes the key to the child as a `[]byte` that cryptkey zeroes as soon as the child exits. `--env` passes the key through the process environment — unavoidably stored as a Go string (immutable, can't be zeroed; lives in the heap until GC) and readable by any same-UID process via `/proc/<pid>/environ` for the child's whole lifetime. Use `--env` only when the target tool has no stdin path for the key. Full rationale in [derive: Secret delivery](commands/derive.md#secret-delivery-stdin-vs-env).

The key is only held in the pipe/environment of the child process — it is not written to disk or visible in your shell history.

## Profile Storage

Profiles are stored as TOML files at:

```
~/.config/cryptkey/<name>.toml
```

A profile contains:

- The Shamir threshold (minimum providers needed to reconstruct)
- Provider type and ID for each enrolled provider
- Encrypted Shamir shares (AES-256-GCM ciphertext)
- Nonces and salts for key derivation
- Provider-specific metadata (e.g., FIDO2 credential IDs, Argon2 salts)
- An integrity HMAC to detect tampering (covers all fields including threshold)

The profile **never** contains the master key, raw secrets, or plaintext shares.

See [Profiles](profiles.md) for what's sensitive, backup strategy, and how to move profiles between machines.
