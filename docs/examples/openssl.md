# OpenSSL

[OpenSSL](https://www.openssl.org/) is ubiquitous for general-purpose symmetric encryption. cryptkey can supply the key or passphrase for its CLI operations over stdin (preferred) or via an environment variable (a weaker transport — see [Secret delivery: stdin vs --env](../commands/derive.md#secret-delivery-stdin-vs-env) for the full reasoning).

## Preferred: pipe to `-pass stdin`

OpenSSL's `-pass stdin` reads a single line from stdin as the passphrase. cryptkey's default hex output fits that exactly: 64 hex characters + newline, which OpenSSL consumes as a 256-bit-entropy passphrase:

```bash
# Encrypt a file
cryptkey derive -- openssl enc -aes-256-cbc -salt -pbkdf2 \
    -in secret.txt -out secret.enc -pass stdin

# Decrypt
cryptkey derive -- openssl enc -aes-256-cbc -d -pbkdf2 \
    -in secret.enc -out secret.txt -pass stdin
```

`cryptkey derive -- <cmd>` runs OpenSSL as a child process with the derived key streamed to its stdin as a caller-owned `[]byte` buffer; cryptkey wipes the buffer from memory as soon as OpenSSL exits. Nothing touches disk, and nothing lingers in the parent process's heap.

## Encrypting a directory

```bash
# Encrypt
tar czf - ~/private/ | cryptkey derive -- \
    openssl enc -aes-256-cbc -salt -pbkdf2 \
    -out private.tar.gz.enc -pass stdin

# Decrypt
cryptkey derive -- \
    openssl enc -aes-256-cbc -d -pbkdf2 \
    -in private.tar.gz.enc -pass stdin | tar xzf -
```

Both the plaintext stream (from `tar`) and the key (from cryptkey) flow through pipes — no intermediate files.

## When you need `-K` (raw key, no KDF)

`-pass stdin` still runs PBKDF2 inside OpenSSL over whatever you hand it. If you want OpenSSL to use the cryptkey-derived 256-bit output *directly* as the AES key — no additional stretching — use `-K <hex>` with cryptkey's default hex output:

```bash
# Encrypt with the cryptkey-derived key as the AES key directly.
# The IV is random per-ciphertext and stored with the ciphertext.
IV_HEX=$(openssl rand -hex 16)
cryptkey derive -- sh -c '
    read -r KEY
    openssl enc -aes-256-cbc -K "$KEY" -iv "'"$IV_HEX"'" \
        -in secret.txt -out secret.enc
'
echo "$IV_HEX" > secret.iv   # IV is not secret

# Decrypt
IV_HEX=$(cat secret.iv)
cryptkey derive -- sh -c '
    read -r KEY
    openssl enc -aes-256-cbc -d -K "$KEY" -iv "'"$IV_HEX"'" \
        -in secret.enc -out secret.txt
'
```

The `sh -c 'read -r KEY; openssl … -K "$KEY" …'` trick pulls the key off stdin into a shell variable local to the subshell. The variable dies with the subshell when OpenSSL exits — no env inheritance across processes.

## HMAC / digest signing

```bash
cryptkey derive -- sh -c 'read -r KEY; openssl dgst -sha256 -hmac "$KEY" -in document.pdf'
```

Same pattern — key pulled off stdin into a scoped shell variable, used inline, scope exits.

## Why not `-pass env:` / `--env KEY`?

OpenSSL also supports `-pass env:VARNAME`, which cryptkey can drive with `cryptkey derive --env KEY -- openssl … -pass env:KEY`. It works. We don't recommend it over stdin:

- Environment variables are readable by any same-UID process (and by root) via `/proc/<pid>/environ` for the entire lifetime of the OpenSSL process. stdin is a pipe — once the child has drained it, the key isn't accessible again.
- Go's `exec.Cmd.Env` is `[]string`-typed. The cryptkey-side copy of the key is unavoidably stored as a Go string, which is immutable and can't be zeroed via `crypto.WipeBytes`; it's left to the garbage collector. The stdin delivery path uses `[]byte` end-to-end and wipes the buffer deterministically when the child exits.

See [Secret delivery: stdin vs --env](../commands/derive.md#secret-delivery-stdin-vs-env) for the fuller explanation. Short version: **use stdin unless the tool literally has no stdin path for the key**.

## Notes

- Always pass `-pbkdf2` when using `-pass stdin` / `-pass env:` — without it, OpenSSL uses its legacy, weak KDF. The `-K <hex>` form bypasses the KDF entirely and uses the key you give it directly.
- `cryptkey derive` produces a 64-character hex string (256 bits of entropy), which OpenSSL happily consumes as either a `-pass stdin` passphrase or a `-K <hex>` raw key.
- The examples use the default profile. Pass a name (`cryptkey derive work -- …`) when you want more than one profile.
- Use `--use` to derive domain-separated keys from the same profile: `cryptkey derive --use photos -- openssl …`, `cryptkey derive --use backups -- openssl …`. Different OpenSSL-encrypted blobs, one cryptkey profile, independent keys.
