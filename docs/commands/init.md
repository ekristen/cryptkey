# cryptkey init

Create a new cryptkey profile by enrolling providers and splitting a master key.

## Usage

```bash
cryptkey init [profile] [options]
```

If `profile` is omitted, cryptkey uses `default`.

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--threshold N`, `-t` | Minimum providers needed to reconstruct the key | `2` |
| `--no-tui` | Disable the interactive terminal UI | `false` |
| `--add type:id`, `-a` | Add a provider (repeatable) | — |
| `--force` | Overwrite an existing profile | `false` |
| `--fido2-uv MODE` | FIDO2 user verification: `discouraged`, `preferred`, `required` | `preferred` |
| `--argon-time N` | Argon2id time/iterations for passphrase and recovery providers | `3` |
| `--argon-memory N` | Argon2id memory in KiB for passphrase and recovery providers | `262144` (256 MiB) |
| `--argon-threads N` | Argon2id parallelism for passphrase and recovery providers | `4` |

## Interactive Mode

By default, `init` launches a terminal UI where you can:

- Browse available providers with arrow keys
- Select a provider with Enter
- Enter an ID for each provider instance
- Enter passphrases with echo suppressed
- View enrolled providers as you go
- Press `d` to finish when the threshold is met

```bash
cryptkey init myprofile
```

## Flag-Driven Mode

When enough `--add` flags are provided to meet the threshold, cryptkey skips interactive mode entirely:

```bash
cryptkey init myprofile \
  --add passphrase:primary \
  --add recovery:backup \
  --add sshkey:~/.ssh/id_ed25519
```

The `--add` flag format is `type:id` where:

- `type` is the provider type name (`passphrase`, `recovery`, `fido2`, `passkey`, `sshkey`, `ssh-agent`)
- `id` is a unique identifier for this provider instance

If `id` is omitted (e.g., `--add passphrase`), one is generated automatically (e.g., `passphrase-1`).

## Simple Interactive Mode

Use `--no-tui` to get a numbered menu instead of the full terminal UI:

```bash
cryptkey init myprofile --no-tui
```

## Examples

### Two passphrases, threshold of 2

```bash
cryptkey init vault \
  --add passphrase:work \
  --add passphrase:personal
```

### Hardware key + passphrase + recovery

```bash
cryptkey init secure
# In the TUI: select fido2, passphrase, and recovery
```

### SSH key as one of the providers

```bash
cryptkey init devkeys \
  --add sshkey:~/.ssh/id_ed25519 \
  --add passphrase:backup
```

### SSH agent (hardware key via agent)

```bash
cryptkey init secure \
  --add ssh-agent:yubikey \
  --add passphrase:backup
```

## What Happens

1. Each provider performs enrollment (generates or collects its secret)
2. A random 32-byte master key is generated
3. The master key is split into `n` Shamir shares (one per provider)
4. Each share is encrypted with its provider's secret
5. An HMAC is computed over the profile data
6. The profile is saved to `~/.config/cryptkey/<profile>.toml`
7. The master key and all secrets are wiped from memory

## Notes

- Provider IDs must be unique within a profile
- You need at least `threshold` providers (minimum 2)
- The profile file can be safely backed up — it contains no plaintext secrets
- Use `--force` to overwrite an existing profile (the old one is permanently lost)
