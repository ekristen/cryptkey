# age

[age](https://age-encryption.org/) is a simple, modern file encryption tool. Cryptkey can materialize an age X25519 identity directly from your profile — no batchpass plugin, no passphrase mode, no separate key file to lose. The identity is **deterministic**: the same profile (with the same `--use` label) always yields the same age key, so you can encrypt today and decrypt tomorrow as long as you can still unlock enough of the profile.

## How it works

Cryptkey's `--age` flag re-derives your profile's master key, runs it through HKDF, and produces a valid age X25519 keypair:

```bash
$ cryptkey derive --age
# created: cryptkey/default/default
# recipient: age1q3js3alsmyhdjcf7myshewgmvpl5j9h3utp7xw6xrp8ycaj8uccsx7un4p
AGE-SECRET-KEY-1GMK8U9UDTC54...ZFMTYZ
```

- stdout carries the age identity (the secret — `AGE-SECRET-KEY-1...`)
- stderr carries the metadata header (recipient + profile comment)

Need only the public side? Use `--age-recipient` — it prints just the `age1...` string with no stderr header, perfect for pipelines.

## Encrypt to your own recipient

No special plumbing: let cryptkey emit the recipient and hand it to `age`.

```bash
# Get the recipient for the "default" profile, encrypt a file to it.
age -r "$(cryptkey derive --age-recipient)" -o secret.age secret.txt
```

You can encrypt without ever unlocking the profile for an interactive derive — the recipient flow only needs the master key transiently and exits quickly. The receiving side (you, later) is what requires unlocking.

## Decrypt with the profile's identity

Pipe the age identity in through stdin via `-i -`:

```bash
cryptkey derive --age -- age -d -i - -o secret.txt secret.age
```

What this does:

1. `cryptkey derive --age` re-derives the identity.
2. `-- age ...` runs `age` as a subprocess; cryptkey sends the identity on the subprocess's stdin.
3. `age -i -` reads the identity from stdin.
4. Cryptkey wipes the identity from memory as soon as `age` exits.

The identity never touches disk and never appears in your shell history.

## Encrypting a directory

Combine with `tar` the same way:

```bash
# Encrypt
tar czf - ~/private/ | age -r "$(cryptkey derive --age-recipient)" -o private.tar.gz.age

# Decrypt
cryptkey derive --age -- sh -c 'age -d -i - -o - private.tar.gz.age | tar xzf -'
```

## Multiple independent identities from one profile

The `--use` label produces a completely different age identity from the same profile:

```bash
cryptkey derive --age-recipient                   # default identity
cryptkey derive --age-recipient --use backups     # a different identity for backups
cryptkey derive --age-recipient --use photos      # another for photos
```

Each label is domain-separated via HKDF — knowing one identity tells an attacker nothing about the others, or about the master key. Store the recipients you need somewhere convenient (a README, a password manager, environment variables in your shell profile); the secret side re-derives on demand.

## Sharing an encrypted file with someone else

When the *sender* isn't you, they don't need cryptkey at all. Publish your recipient (it's a public key) and they use plain `age`:

```bash
# Publish once — this is safe to share.
cryptkey derive --age-recipient > my-recipient.txt

# Someone else encrypts to you with vanilla age.
age -r "$(cat my-recipient.txt)" -o file.age file.txt
```

You decrypt with `cryptkey derive --age -- age -d -i - -o ...` as above.

## SOPS and other tools that accept age identities

Any tool that takes an age identity file path will also accept `/dev/stdin` or a process-substitution path. For example, [SOPS](sops.md) with age works with cryptkey the same way — see its example page for the exact wiring.

## Notes

- **The identity is deterministic.** `cryptkey rekey` preserves the profile's master key (and its `output_salt`) by design — it only reshuffles which providers hold shares. That means every derived age identity stays valid across rekeys. If you have existing `age`-encrypted files, you do not need to re-encrypt them when you rotate providers.
- **age's own scrypt passphrase mode is unnecessary here.** The key material is already stretched by Argon2id (for passphrase/recovery providers) and HKDF; running it through scrypt again adds latency without changing the security picture.
- **For an at-rest backup of the identity**, you can still do `cryptkey derive --age > identity.age.file`, but generally you don't need to — the profile *is* your identity backup.
