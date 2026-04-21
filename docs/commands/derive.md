# cryptkey derive

Reconstruct the master key by authenticating with enough providers to meet the threshold, then output a derived key — or exec a command with it.

## Usage

```bash
# Emit key to stdout
cryptkey derive [profile] [options]

# Exec a command with the key on stdin
cryptkey derive [profile] [options] -- <command> [args...]

# Exec a command with the key as an environment variable
cryptkey derive [profile] --env VAR [options] -- <command> [args...]
```

If `profile` is omitted, cryptkey uses `default`.

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--raw` | Output raw bytes | off (hex) |
| `--base64` | Output base64-encoded key | off (hex) |
| `--age` | Output an age X25519 identity (secret key to stdout, recipient to stderr) | off |
| `--age-recipient` | Output only the age recipient (public key) for use with `age -r` | off |
| `--ed25519` | Output an OpenSSH ed25519 private key (PEM to stdout, public key to stderr) | off |
| `--format FORMAT` | Output key format: `age`, `age-recipient`, `ed25519` | — |
| `--env VAR`, `-e` | Pass key as this environment variable instead of stdin (requires `-- command`) | — (stdin) |
| `--use LABEL` | Context label for deriving a purpose-specific key | `default` |
| `--provider TYPE` | Only attempt these providers (repeatable) | all |
| `--skip TYPE` | Skip these providers (repeatable) | none |
| `--quiet`, `-q` | Suppress all stderr output except fatal errors | off |
| `--timeout DURATION` | Hardware provider timeout | provider-specific |

`--raw`, `--base64`, `--age`, `--age-recipient`, and `--ed25519` are mutually exclusive. If neither is set, output is hex-encoded.

## Examples

### Emit key to stdout

```bash
# Hex output (default)
cryptkey derive myprofile
# Output: a1b2c3d4e5f6...

# Base64 output
cryptkey derive myprofile --base64

# Raw bytes to a file
cryptkey derive myprofile --raw > /tmp/keyfile
```

### Exec a command

```bash
# Pass key on stdin
cryptkey derive myprofile -- my-tool --key-stdin

# Pass key as an environment variable
cryptkey derive myprofile --env SECRET_KEY -- ./run.sh

# Raw bytes on stdin
cryptkey derive myprofile --raw -- my-tool --key-file /dev/stdin

# Multiple tools via shell
cryptkey derive myprofile --env KEY -- sh -c 'echo "Key is ${#KEY} chars"'
```

### Age encryption

```bash
# Encrypt a file (recipient piped to age -R -)
cryptkey derive myprofile --age-recipient -- age -e -R - -o secret.age secret.txt

# Decrypt a file (identity piped to age -i -)
cryptkey derive myprofile --age -- age -d -i - -o secret.txt secret.age
```

### Purpose-specific keys

Derive different keys from the same profile using `--use`:

```bash
# Default key (same as --use default)
cryptkey derive myprofile

# A different key for disk encryption
cryptkey derive myprofile --use disk

# Another for encrypting backups
cryptkey derive myprofile --use backups
```

Each `--use` value produces a completely different key from the same master key, via HKDF domain separation.

## What Happens

1. The profile is loaded from `~/.config/cryptkey/<profile>.toml`
2. For each provider in the profile, cryptkey attempts to re-derive the secret:
    - Passphrase providers prompt for the passphrase
    - FIDO2 providers prompt for a key touch
    - Recovery providers prompt for the recovery code
    - SSH key providers read the key file (prompting for passphrase if encrypted)
    - SSH agent providers have the agent sign a deterministic challenge
    - TPM providers compute an HMAC via the TPM's hardware-bound key
    - Passkey providers open a browser window
3. Each successful secret decrypts its Shamir share
4. Once the threshold number of shares are decrypted, Shamir recombines them into the master key
5. The profile's HMAC is verified against the reconstructed master key
6. The output key is derived from the master key via HKDF-SHA256
7. All secrets, shares, and the master key are wiped from memory

## Secret delivery: stdin vs --env

Both `-- <command>` on stdin and `--env VAR -- <command>` deliver the derived key to the child process. They're **not** equivalent from a memory-hygiene standpoint:

- **stdin** is the preferred transport. cryptkey hands the key to the child through a pipe as a `[]byte` buffer that is explicitly zeroed as soon as the child exits — nothing referencing the plaintext key outlives the call.
- **`--env VAR`** passes the key through the process environment. Go's `os/exec` takes `Env []string`, and strings in Go are immutable, so cryptkey can't zero its copy — it's left for the garbage collector. More importantly, the environment variable lives in the **child** process's memory for the full duration of that process and is readable by any same-UID process (and by root) via `/proc/<pid>/environ`. Only use `--env` when the target tool has no stdin path for the key.

Some tools let you read from `/dev/stdin` as a keyfile (e.g. `gocryptfs -extpass`, `veracrypt --keyfiles=/dev/stdin`); prefer those over an env-var path when both exist.

## Output Key Derivation

The output key is not the raw master key. It is derived using:

```
HKDF-SHA256(master_key, output_salt, "cryptkey:<use>") -> output_key
```

- **Salt**: a random 32-byte value generated at profile creation and stored in the profile
- **Info**: `cryptkey:<use>` where `<use>` defaults to `default`
- **Output**: always 32 bytes (256 bits)

The profile name is intentionally **not** part of the info string. Profile files are not pinned — renaming `~/.config/cryptkey/foo.toml` to `bar.toml` would otherwise silently change every derived key. Per-profile domain separation comes from the per-profile random `output_salt` instead, which is locked into the profile content.

### Why This Is Secure

HKDF (HMAC-based Key Derivation Function) is a standard construct ([RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)) designed specifically for deriving multiple independent keys from a single secret. It provides two guarantees that make `--use` safe:

- **Cryptographic independence**: Each distinct `--use` label produces a key that is computationally indistinguishable from random. Knowing one derived key reveals nothing about any other derived key — or the master key itself.
- **Domain separation**: The combination of the per-profile random `output_salt` and the `cryptkey:<use>` info string ensures that keys derived for different purposes or profiles can never collide, even when they share the same set of providers.

This means you can safely derive as many purpose-specific keys as you need from a single profile without weakening any of them. For example, using `--use disk` for disk encryption and `--use backups` for backup encryption produces two fully independent 256-bit keys, both backed by the same set of providers and threshold.

## Exec Mode

When a command follows `--`, cryptkey derives the key and passes it to the child process:

- **Without `--env`**: the formatted key is passed on the child's **stdin**
- **With `--env VAR`**: the formatted key is set as environment variable `VAR`, and stdin is passed through from the parent

The child's exit code becomes cryptkey's exit code. The key is only held in the child's environment or stdin — it is not written to disk or visible in your shell history.

## Error Handling

- If a provider fails (wrong passphrase, missing hardware key), cryptkey skips it and tries the next
- If fewer than `threshold` providers succeed, derivation fails
- If the HMAC check fails after reconstruction, the profile may be corrupted or tampered with
