# SOPS

[Mozilla SOPS](https://github.com/getsops/sops) encrypts individual values inside structured files (YAML, JSON, ENV, INI) and supports [age](https://age-encryption.org/) as one of its backends. cryptkey can produce the age identity SOPS uses — derived deterministically from your profile — so unlocking SOPS-encrypted secrets requires authenticating with your enrolled providers.

## How it works

cryptkey's `--age` output is a fully valid age X25519 identity, derived from the profile's master key via HKDF. You don't generate a separate age keypair; cryptkey *is* the key generator:

- **Private half** (`AGE-SECRET-KEY-1…`): re-derived on demand via `cryptkey derive --age`. Lives in process memory for the life of one SOPS invocation; never on disk.
- **Public half** (`age1…`): the recipient string you put in `.sops.yaml`. Derivable with `cryptkey derive --age-recipient` without a full unlock when you just need to know where to encrypt to.

Because `rekey` preserves the profile's master key and `output_salt`, the age identity stays stable across provider rotations — SOPS files encrypted today keep decrypting after you swap out providers.

## Setup

### 1. Create a cryptkey profile (if you don't have one)

```bash
cryptkey init
# Enroll at least 2 providers with threshold 2 — see Getting Started.
```

### 2. Put the recipient in `.sops.yaml`

The recipient is a public value; commit it with the repo. Generate it once:

```bash
RECIPIENT=$(cryptkey derive --age-recipient)
cat > .sops.yaml <<EOF
creation_rules:
  - age: "$RECIPIENT"
EOF
```

Or with a specific `--use` label so SOPS uses a separate domain-separated key from the rest of the profile:

```bash
RECIPIENT=$(cryptkey derive --age-recipient --use sops)
# … same .sops.yaml write as above.
```

That's the whole setup. No `age-keygen`, no encrypted keyfile on disk, no plugin to install.

## Encrypting

Encryption only needs the public recipient, which SOPS reads from `.sops.yaml` — no cryptkey involved:

```bash
sops -e secrets.plaintext.yaml > secrets.yaml
```

## Decrypting

SOPS accepts an age identity via the `SOPS_AGE_KEY_FILE` environment variable. Point it at `/dev/stdin` and stream the identity in through cryptkey's `--` exec:

```bash
# Decrypt to stdout
cryptkey derive --age -- sh -c 'SOPS_AGE_KEY_FILE=/dev/stdin sops -d secrets.yaml'

# Extract a single value
cryptkey derive --age -- sh -c 'SOPS_AGE_KEY_FILE=/dev/stdin sops -d --extract "[\"database\"][\"password\"]" secrets.yaml'
```

The identity flows from cryptkey's `--age` output into the subshell's stdin, which `SOPS_AGE_KEY_FILE=/dev/stdin` tells SOPS to read as its keyfile. Nothing touches disk; cryptkey zeroes its `[]byte` copy of the identity as soon as SOPS exits.

If you're on a label other than the default:

```bash
cryptkey derive --age --use sops -- sh -c 'SOPS_AGE_KEY_FILE=/dev/stdin sops -d secrets.yaml'
```

## Editing

SOPS edits in place by opening `$EDITOR` on the decrypted content and re-encrypting on save. Same plumbing:

```bash
cryptkey derive --age -- sh -c 'SOPS_AGE_KEY_FILE=/dev/stdin sops secrets.yaml'
```

## Wrapper function

Drop this in your shell rc if you SOPS often:

```bash
sops-cryptkey() {
    cryptkey derive --age -- sh -c \
        'SOPS_AGE_KEY_FILE=/dev/stdin exec sops "$@"' _ "$@"
}

# Usage:
sops-cryptkey -d secrets.yaml
sops-cryptkey secrets.yaml          # edit
sops-cryptkey -d --extract '["database"]["password"]' secrets.yaml
```

## Why not `SOPS_AGE_KEY` (env var)?

SOPS also accepts the identity directly via `SOPS_AGE_KEY=<identity>` rather than a keyfile path. You'd write:

```bash
SOPS_AGE_KEY=$(cryptkey derive --age) sops -d secrets.yaml
```

This works but is the weaker transport — the identity lives as a shell-variable string in the process environment (readable via `/proc/<pid>/environ` by any same-UID process for the whole lifetime of the sops child) and cryptkey can't zero its side of the copy because env vars are Go strings. Use the `SOPS_AGE_KEY_FILE=/dev/stdin` form above unless something's blocking the stdin path. Full rationale in [derive: Secret delivery](../commands/derive.md#secret-delivery-stdin-vs-env).

## CI / unattended decryption

cryptkey is designed for interactive multi-factor unlock; every provider except TPM wants either a prompt, a hardware touch, or a browser interaction. That doesn't fit the "fully unattended build runner" pattern. Two honest options:

- **Dedicated CI identity outside cryptkey.** Generate a plain `age-keygen` identity, store it in your CI provider's secrets manager, inject as `SOPS_AGE_KEY` in the CI job, use it for that environment only. Your local developer workflow still uses cryptkey; CI uses its own identity. Add both recipients to `.sops.yaml`'s `age:` list so files encrypt for both.
- **TPM-only profile on a long-lived build host.** If the CI runner is a dedicated box with a TPM, a cryptkey profile with just a `tpm` provider unlocks non-interactively (TPM does its own HMAC without user input). Works but binds decryption to that specific chip — not portable across runners.

Don't try to bolt `echo "$CI_SECRET" | cryptkey derive …` patterns onto the passphrase provider; the interactive prompt path doesn't read from piped stdin in a way that'll survive future changes, and it conflates cryptkey's threat model ("human authenticates with multiple factors") with a fundamentally different one ("build agent holds a single secret in its environment").

## Notes

- Encryption (`sops -e`) never needs cryptkey — only the public recipient in `.sops.yaml`.
- `cryptkey derive --age` is deterministic for a given profile + `--use` label, so a freshly-cloned repo on a new machine with the same profile produces the same identity and decrypts existing SOPS files.
- The same machine note applies as elsewhere: "same profile" means the profile TOML *and* the ability to unlock enough providers. TPM-bound providers don't migrate between machines; re-derive a replacement via `cryptkey rekey` before moving.
- Pair `--use sops` with other `--use` labels (`--use disk`, `--use backups`) to keep SOPS's identity domain-separated from your other cryptkey-derived keys.
