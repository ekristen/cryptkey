# Security Model

## Threat Model

Cryptkey is designed to protect a master encryption key such that:

- **No single provider compromise** reveals the key
- **No single provider loss** prevents recovery
- **No server or online service** is required
- **No plaintext secrets** are stored on disk

### What Cryptkey Protects Against

| Threat | Mitigation |
|--------|------------|
| Theft of one hardware key | Attacker has 1 share; needs `threshold` to reconstruct |
| Forgotten passphrase | Other providers can still meet the threshold |
| Lost/destroyed hardware | Recovery codes and passphrases survive hardware loss |
| Profile file theft | Shares are AES-256-GCM encrypted; useless without provider secrets |
| Profile tampering | HMAC-SHA256 integrity check detects modification |
| Memory forensics | Secrets are explicitly zeroed after use (best-effort; see note below) |

### What Cryptkey Does Not Protect Against

| Threat | Why |
|--------|-----|
| Compromise of `threshold` providers simultaneously | By design — the threshold is the security/availability tradeoff |
| Malware on the machine during key derivation | The master key exists in process memory briefly during derivation |
| Side-channel attacks on the local machine | Standard Go crypto; no constant-time guarantees beyond what the stdlib provides |
| Quantum attacks on AES-256 / SHA-256 | AES-256 has 128-bit post-quantum security (Grover's); SHA-256 is similarly reduced but still considered safe |

## Cryptographic Choices

### Why AES-256-GCM?

AES-256-GCM provides authenticated encryption — both confidentiality and integrity in a single operation. The authentication tag prevents an attacker from modifying ciphertext without detection, even without the separate HMAC layer.

### Why HKDF?

HKDF (HMAC-based Key Derivation Function) is used to derive AES keys from provider secrets. It separates the "extraction" step (making the key uniform) from the "expansion" step (deriving the right-length key). Each derivation uses:

- A unique random salt (stored in the profile)
- A context-specific info string (`"cryptkey-share-encryption"` for shares, `"cryptkey:<use>"` for output)

This ensures that the same provider secret produces different AES keys for different purposes.

### Why Argon2id?

Passphrase and recovery code providers use Argon2id to stretch human-memorizable inputs into 32-byte keys. Argon2id is the recommended password hashing function — it resists both GPU attacks (memory-hard) and side-channel attacks (data-independent memory access in the first pass).

Default parameters are hardened for long-term disk-at-rest protection: 3 iterations, 256 MiB memory, 4 threads. These are stored per-provider in the profile, so different providers can use different settings. At derive time cryptkey enforces OWASP's recommended minimum (`t=2, m=19 MiB, p=1`) as a floor so a tampered profile cannot request weaker parameters than that baseline.

On a modern laptop the defaults take roughly 500 ms — imperceptible during `derive`. If you need faster unlocks (or you're targeting a lower-powered device) you can dial the cost down at enrollment:

```bash
# OWASP minimum — fastest, still resists GPU brute force
cryptkey init myprofile --argon-memory 19456 --argon-time 2 --argon-threads 1 \
  --add passphrase:primary --add passphrase:backup
```

Higher memory makes each Argon2id evaluation slower for both you and an attacker. Since cryptkey only runs derivation once per unlock, a 1-2 second delay is acceptable — the aggressive defaults trade that latency for ~25× the attacker work factor versus the OWASP floor.

### Why Shamir over GF(256)?

Operating over GF(256) means each byte is split independently. This avoids big-integer arithmetic and makes the implementation simpler and constant-time at the field level. The tradeoff is that shares are the same size as the secret (32 bytes), which is acceptable for this use case.

## Profile Security

For the full treatment — what's in a profile, backup strategies, cross-system migration, sharing between users, threat model for a leaked profile — see [Profiles](profiles.md). The short version:

### What's Stored

The profile TOML file contains only:

- The Shamir threshold
- Encrypted share ciphertext (AES-256-GCM)
- GCM nonces and HKDF salts
- Provider metadata (credential IDs, Argon2 salts, SSH key fingerprints)
- An HMAC of all the above (including threshold)

### What's Never Stored

- The master key
- Plaintext Shamir shares
- Provider secrets (passphrase bytes, FIDO2 hmac-secret output, SSH private key material)
- Recovery codes

### Integrity Verification

The profile includes an HMAC-SHA256 computed over all provider data, keyed by a value derived from the master key via HKDF. This means:

- An attacker who modifies the profile will be detected at derive time.
- The HMAC key is not stored — it can only be computed by someone who reconstructs the master key.
- The HMAC covers the threshold, provider types, IDs, ciphertext, nonces, salts, `output_salt`, and all params.

#### Why an HMAC when every share already has AES-256-GCM?

Per-share GCM authenticates each encrypted Shamir share individually — flip a bit in any `encrypted_share`, `nonce`, or `share_salt` and GCM refuses to decrypt. So GCM covers the *ciphertext bytes*. The HMAC's job is the fields GCM can't cover:

- `threshold` — the integer itself.
- `output_salt` — the per-profile salt that feeds every `--use` output key.
- `name`, provider `type` / `id`, and the ordering of the provider list.
- The HMAC tag itself (if you could rewrite the HMAC field, you could silence tampering elsewhere).

Those aren't inside any encrypted blob, so without the HMAC they'd be mutable by anyone with profile write access — no brute force, no decryption, just editing the TOML.

#### Why the check happens *after* unlock

The HMAC is keyed by the master key, so yes, you have to reconstruct the master key before you can verify. That means the "expensive" provider-auth work happens before verification. The defense-in-depth isn't about stopping you from unlocking — it's about stopping an attacker from silently redirecting the *output* once you have unlocked.

Concrete attack without the HMAC: an attacker with write access to `~/.config/cryptkey/default.toml` (cloud-synced, shared workstation, stolen disk) replaces `output_salt` with a value `S'` of their choice. You unlock normally — the shares haven't been touched, Shamir combines to your real master key — and cryptkey computes `output_key = HKDF(master_key, S', "cryptkey:<use>")`. The attacker pre-computed a catalog of what output keys each candidate `S'` yields; when you encrypt data with your output key, they decrypt it.

With the HMAC: the attacker cannot recompute a valid HMAC over their edited profile because they don't have the master key. Cryptkey recomputes the HMAC against the reconstructed master key at derive time; if they don't match, derivation aborts before emitting the output key. Tampering becomes "integrity error, try again" (recoverable annoyance) instead of "silent encryption under an attacker-chosen key" (catastrophic).

## Provider-Specific Security

### FIDO2

- Uses the `hmac-secret` extension to derive a deterministic 32-byte secret from the hardware key
- The secret is bound to a credential ID stored in the profile
- Requires physical presence (touch) for each operation
- The credential ID alone is useless without the hardware key

### Passkey

- Uses the WebAuthn PRF (Pseudo-Random Function) extension via a local browser
- Secrets are derived from browser-managed credentials
- CSRF protection via state tokens during the browser flow

### Passphrase

- Argon2id stretching with a random 32-byte salt
- Terminal echo is suppressed during input
- Passphrase bytes are wiped from memory after derivation

### Recovery Code

- 42-character code from an unambiguous alphabet (A-Z minus O/I/L, digits 2-9)
- ~217 bits of entropy
- Displayed once during enrollment, never stored
- Argon2id stretched like passphrases

### SSH Key

- Derives a secret from the private key material via HKDF-SHA256
- Stores the key's SHA256 fingerprint; verifies it matches at derive time
- Supports passphrase-protected keys (prompts for decryption)
- Supports Ed25519, ECDSA, and RSA key types
- Private key bytes are wiped from memory after derivation

## Shamir Threshold Security

Shamir's Secret Sharing provides **information-theoretic security**: if the threshold is M, then M-1 or fewer shares reveal *literally zero information* about the master key. This is a stronger guarantee than most cryptography.

With computational security (e.g. AES), an attacker with infinite time could theoretically brute-force the key. With Shamir, even an attacker with infinite computing power and M-1 shares cannot narrow down what the master key is. Every possible key value is equally consistent with the shares they hold.

This means:

- **Below threshold = zero knowledge.** An attacker who compromises one provider in a threshold-2 profile learns nothing about the master key.
- **At threshold = complete recovery.** The moment you reach M shares, you reconstruct the key with certainty.
- **The threshold is stored in the profile** and covered by the integrity HMAC, so it cannot be tampered with. Knowing the threshold does not weaken Shamir's information-theoretic guarantee — an attacker with fewer than M shares still learns nothing about the master key regardless of whether they know M.

### Minimum Threshold

The minimum threshold is always **2**. A threshold of 1 would mean any single share recovers the secret — that's equivalent to storing the key in plaintext. Cryptkey enforces this in code.

## Threshold Planning

The threshold controls the tradeoff between security (how many providers an attacker must compromise) and availability (how many can fail before you're locked out).

| Setup | Threshold | Providers | Fault tolerance | Use case |
|---|---|---|---|---|
| Minimum | 2 | 2 | None — both must work | Testing, low-risk keys |
| Recommended | 2 | 3-4 | Lose 1-2 and still recover | Personal encryption |
| High security | 3 | 5+ | Need 3, can lose 2+ | Critical infrastructure |

### Recovery Planning

!!! warning "Plan for total hardware loss"
    If all your hardware providers (FIDO2 keys, passkey devices) are lost, stolen, or destroyed simultaneously, you need enough non-hardware providers (passphrases, recovery codes) to still meet the threshold.

    **Rule: Enroll at least `threshold` non-hardware providers.**

    Cryptkey warns you during enrollment if this isn't the case.

Example setups:

=== "Personal (recommended)"
    - 1x FIDO2 (YubiKey)
    - 1x passphrase (memorized)
    - 1x recovery code (written down, stored in safe)
    - Threshold: 2

    Lose your YubiKey? Passphrase + recovery code. Forget your passphrase? YubiKey + recovery code.

=== "Two hardware keys"
    - 2x FIDO2 (primary + backup YubiKey)
    - 1x passphrase
    - 1x recovery code
    - Threshold: 2

    Any two of four providers work. Both YubiKeys lost? Passphrase + recovery code.

=== "High security"
    - 2x FIDO2 (separate locations)
    - 1x passphrase
    - 2x recovery code (separate locations)
    - Threshold: 3

    Attacker must compromise 3 of 5 providers. You can lose any 2 and still recover.

## Recommendations

1. **Use at least 3 providers with a threshold of 2** — this gives you redundancy without requiring every provider at every unlock.

2. **Include at least `threshold` non-hardware providers** — passphrases and recovery codes survive hardware loss. Cryptkey warns you if your threshold can't be met without hardware.

3. **Store recovery codes physically** — print them or write them down. Don't store them digitally alongside your profile.

4. **Use different passphrases** for each passphrase provider in the same profile.

5. **Back up your profile file** — it contains no secrets, only encrypted shares. Losing it means losing access even if you have all your providers.

6. **FIDO2 keys can be reused across profiles** — each profile generates a unique salt, so the same hardware key produces independent secrets per profile. The only risk is availability: losing that key affects all profiles it's enrolled in.
