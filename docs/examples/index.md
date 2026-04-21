# Examples

Cryptkey derives encryption keys — it doesn't encrypt anything itself. These examples show how to pair it with popular encryption tools.

In each example, cryptkey manages the key lifecycle (splitting it across providers, reconstructing it on demand) while the encryption tool does the actual data protection.

## Tools Covered

- [gocryptfs](gocryptfs.md) — Encrypted overlay filesystem (FUSE-based, file-level encryption)
- [age](age.md) — Simple, modern file encryption
- [VeraCrypt](veracrypt.md) — Full-disk / container encryption
- [LUKS](luks.md) — Linux disk encryption
- [OpenSSL](openssl.md) — General-purpose encryption toolkit
- [SOPS](sops.md) — Encrypted secrets in YAML/JSON files (via age backend)

!!! note "Why no git-crypt example?"
    [git-crypt](https://github.com/AGWA/git-crypt) generates its own symmetric key at `git-crypt init` — there's no hook to supply an externally-derived key — and only supports *adding* GPG recipients to that pre-generated key. Any "cryptkey + git-crypt" recipe would be "use cryptkey to encrypt git-crypt's exported keyfile at rest," which is the [age](age.md) or [OpenSSL](openssl.md) blob-at-rest pattern, not a git-crypt integration.

## General Pattern

Most integrations follow the same pattern:

```bash
# Initial setup: create the default cryptkey profile
cryptkey init

# Use the derived key with your tool
cryptkey derive --env KEY -- <tool> <args>

# Or derive and pipe manually
cryptkey derive --raw -- <tool> --key-file /dev/stdin
```

Omitting the profile name uses `default`. Pass an explicit name (e.g. `cryptkey init work` / `cryptkey derive work`) when you want more than one profile per user.

!!! note "Key format"
    `cryptkey derive` outputs hex by default. Use `--raw` for raw bytes or `--base64` for base64 encoding. When using `-- command`, the key is passed as a **hex-encoded string** in the environment variable or on stdin.

!!! tip "Prefer `-- <tool>` over a shell pipe"
    Running the tool via cryptkey's `--` exec (rather than `cryptkey derive | tool`) avoids a race for `/dev/tty` between cryptkey's provider prompts and anything the tool (or an intermediary like `sudo`) wants to prompt for. cryptkey finishes its own prompts first, *then* execs the child. See the [VeraCrypt example](veracrypt.md#why-not-just-pipe) for a concrete case.
