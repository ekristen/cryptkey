# gocryptfs

[gocryptfs](https://nuetzlich.net/gocryptfs/) is a FUSE-based encrypted overlay filesystem. Files are encrypted individually, making it friendly to cloud sync (Dropbox, Syncthing, etc.).

## Setup

### 1. Create a cryptkey profile

```bash
cryptkey init
# Enroll at least 2 providers (e.g., passphrase + recovery)
```

Omitting the profile name writes to the `default` profile, which every subsequent cryptkey command also falls back to. Pass a name (e.g. `cryptkey init vault`) if you want to keep a separate profile per purpose.

### 2. Initialize gocryptfs with the derived key

gocryptfs accepts a passphrase on stdin via `-extpass`. We use `cryptkey derive` as the external password command:

```bash
mkdir -p ~/encrypted ~/decrypted

gocryptfs -init -extpass "cryptkey derive --raw" ~/encrypted
```

This creates the gocryptfs config in `~/encrypted/` using the cryptkey-derived key as the master passphrase.

### 3. Mount

```bash
gocryptfs -extpass "cryptkey derive --raw" ~/encrypted ~/decrypted
```

### 4. Unmount

```bash
fusermount -u ~/decrypted
```

## Shell aliases

Add to your shell profile for convenience:

```bash
alias vault-mount='gocryptfs -extpass "cryptkey derive --raw" ~/encrypted ~/decrypted'
alias vault-umount='fusermount -u ~/decrypted'
```

If you maintain multiple gocryptfs vaults, use a named profile per vault and reference it explicitly — e.g. `cryptkey derive work --raw` vs `cryptkey derive personal --raw`.

## How it works

```
cryptkey derive --raw
    │
    │  (raw 32-byte key on stdout)
    ▼
gocryptfs -extpass "..." ~/encrypted ~/decrypted
    │
    │  (uses key as master passphrase)
    ▼
FUSE mount at ~/decrypted
```

gocryptfs's `-extpass` flag runs the specified command and reads the passphrase from its stdout. `cryptkey derive --raw` writes the raw 32-byte key to stdout, which gocryptfs consumes.

## Notes

- The `-extpass` command is run each time you mount — you'll authenticate with your cryptkey providers each time.
- gocryptfs has its own key derivation internally (scrypt by default), so the cryptkey-derived key is stretched again before use.
- The encrypted directory (`~/encrypted/`) can be safely synced to cloud storage.
