# FAQ

## Is cryptkey FIPS 140-3 compliant?

**Short answer: no, and compiling with Go's FIPS toolchain wouldn't change that in a useful way.**

### Why not

Cryptkey leans on algorithms that are outside FIPS 140-3's approved list:

- **Argon2id** (passphrase and recovery providers) — not a FIPS-approved KDF. The entire brute-force resistance of those providers depends on Argon2's memory-hardness; FIPS's approved KDFs (PBKDF2, SP 800-56C two-step KDF) are compute-hard but not memory-hard and can't substitute without weakening the security story.
- **X25519** (the `--age` and `--age-recipient` output formats) — not on the FIPS-approved curve list. The age ecosystem is Curve25519-based throughout.
- **Curve25519-based Ed25519** variants used by some OpenSSH paths — same situation.

The FIPS-approved primitives cryptkey *does* use (AES-256-GCM, HKDF-SHA256, HMAC-SHA256) are real, but they're not the pieces that define the security ceiling. Building with `GODEBUG=fips140=on` would route those through Go's FIPS-validated module while Argon2 and X25519 continue to run as non-approved code in the same binary — which is a confusing middle ground that wouldn't pass a serious compliance review.

### What you can do today if you need FIPS compliance

Hardware providers do their own crypto on the device, outside Go's scope:

- **FIDO2** — YubiKey sells a [FIPS Series](https://www.yubico.com/products/yubikey-fips/) whose `hmac-secret` extension runs on FIPS 140-3-certified firmware.
- **PIV** — many smartcards (including YubiKey FIPS) carry FIPS-certified PIV applets.
- **TPM 2.0** — most modern TPM chips ship with FIPS 140-3 certifications from their manufacturer.

If you need a FIPS-compliant cryptkey deployment *right now*, the practical path is:

1. Build a profile using only hardware providers (FIDO2 / PIV / TPM) on FIPS-certified devices.
2. Do not enroll passphrase, recovery, sshkey, sshagent, or passkey providers, and do not use `--age` / `--age-recipient` output formats.
3. Note that the *remaining* Go-side crypto cryptkey runs (AES-GCM for share encryption, HKDF-SHA256 for key derivation, HMAC-SHA256 for integrity) is FIPS-approved; routing it through Go's FIPS module is possible but adds no guarantees beyond what the stdlib already provides.

This isn't a formally validated configuration — no NIST CMVP certificate has been issued for a cryptkey binary. It's an "approved-primitives-only" deployment, which is typically what compliance review actually cares about in practice.

### What a future `-tags fips` build could look like

If there's concrete demand, a compile-time `fips` build tag could enforce the above at link time:

- Refuses to include the passphrase, recovery, sshkey, sshagent, and passkey providers.
- Disables the `--age` and `--age-recipient` output formats.
- Keeps FIDO2 / PIV / TPM.
- Builds against Go's FIPS-validated module and enables it by default.

That would give you a restricted but coherent binary. No one has asked for it yet, so it isn't built — file an issue with your specific compliance constraints if you need it, and it can be scoped against real requirements rather than guesses.

### What a NIST-certified cryptkey would take

Formal FIPS 140-3 validation is a separate, expensive, time-consuming process (NIST CMVP testing, documentation, and certificate issuance on the exact compiled binary). That's a product decision, not a toolchain flag. It's not currently on the roadmap.
