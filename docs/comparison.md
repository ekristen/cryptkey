# Comparison

cryptkey occupies a unique niche: **threshold-based key derivation from multiple authentication providers, entirely offline**. This page compares it to tools you might consider for similar use cases.

## At a Glance

| Tool | Type | Server Required | Shamir/Threshold | Multi-Provider Auth | Offline | Best For |
|------|------|:-:|:-:|:-:|:-:|------|
| **cryptkey** | Key derivation | No | Yes | Yes (FIDO2, passkeys, passphrase, recovery, SSH, TPM) | Yes | Personal key management |
| **HashiCorp Vault** | Secrets engine | Yes | Unseal only | Auth backends (LDAP, OIDC, etc.) | No | Enterprise secrets |
| **age** | File encryption | No | No | Multiple recipients (OR) | Yes | Simple file encryption |
| **age-plugin-sss** | age plugin | No | Yes | age recipients only | Yes | Threshold file encryption |
| **SOPS** | Config encryption | Partial | No | Multiple key backends | With PGP/age | Secrets in git |
| **pass / gopass** | Password store | No | No | GPG/age key only | Yes | Password management |
| **KeePassXC** | Password database | No | No | Password + YubiKey (2FA) | Yes | Password management |
| **1Password CLI** | Password manager | Yes | No | Biometric + password | Limited | Personal / team secrets |
| **Bitwarden CLI** | Password manager | Yes | No | Master password + 2FA | Read-only | Personal / team secrets |
| **ssss** | Secret sharing | No | Yes | No | Yes | Splitting raw secrets |
| **Horcrux** | File splitting | No | Yes | No | Yes | File backup/distribution |
| **systemd-cryptenroll** | Disk encryption | No | No | FIDO2, TPM, passphrase (OR) | Yes | LUKS unlock |
| **fido2-hmac-secret** | Key derivation | No | No | Single FIDO2 token | Yes | Single-device key derivation |

## Detailed Comparisons

### vs. HashiCorp Vault

Vault is the industry standard for enterprise secret management. It uses Shamir's Secret Sharing -- but only to protect its unseal key, not as a user-facing feature for key derivation.

| | cryptkey | HashiCorp Vault |
|---|---|---|
| **Setup** | `cryptkey init` | Server deployment, TLS, storage backend, policies |
| **Infrastructure** | None (single binary) | Server process, storage (Consul/Raft/etc.), network |
| **Auth for key access** | FIDO2, passkeys, passphrase, SSH keys, TPM | LDAP, OIDC, AppRole, tokens, certificates |
| **Shamir usage** | Core feature -- threshold of providers reconstruct key | Unseal key only |
| **Secrets management** | Derives a single key per profile | Dynamic secrets, PKI, transit encryption, KV store |
| **Audit** | Local TOML profiles | Full audit logging, ACL policies |
| **Use case** | Personal encryption key derivation | Team/enterprise secrets infrastructure |

**Choose Vault** if you need dynamic secrets, team access control, audit logging, or secret rotation. **Choose cryptkey** if you want offline, personal key derivation without running infrastructure.

### vs. age / age-plugin-sss

age is the closest tool in philosophy: simple, modern, no config. The `age-plugin-sss` plugin adds Shamir threshold support on top of age.

| | cryptkey | age | age-plugin-sss |
|---|---|---|---|
| **Purpose** | Derive a key from multiple auth providers | Encrypt files to recipients | Threshold file encryption |
| **Threshold scheme** | Yes (core design) | No (any recipient decrypts) | Yes (Shamir over age recipients) |
| **Auth providers** | FIDO2 hmac-secret, passkeys, passphrases, SSH keys, TPM, recovery codes | age keys, SSH keys, passphrases, plugins | Whatever age recipients support |
| **FIDO2 support** | Native (hmac-secret extension) | Via plugin | Via plugin |
| **Output** | Raw key bytes (pipe to any tool) | Encrypted file | Encrypted file |
| **Key persistence** | Encrypted shares in TOML profile | Recipient public keys | Shares as age recipients |

**Choose age** if you want simple file encryption. **Choose cryptkey** if you need threshold-based key derivation across diverse auth methods, with the output key usable for anything (LUKS, gocryptfs, age, SOPS, etc.).

### vs. SOPS

SOPS encrypts individual values in config files using cloud KMS, PGP, or age keys. It's designed for secrets-in-git workflows.

| | cryptkey | SOPS |
|---|---|---|
| **Purpose** | Derive encryption key | Encrypt config file values |
| **Key source** | Multiple auth providers (threshold) | AWS/GCP/Azure KMS, PGP, age |
| **Offline** | Always | Only with PGP/age |
| **Threshold** | Yes | Key groups (all groups required, not threshold) |
| **Team use** | Single user | Multi-user via shared KMS/PGP |
| **Integration** | Pipe key to any tool | Direct YAML/JSON/ENV editing |

These tools are complementary -- you can use cryptkey to derive an age key, then use that key with SOPS.

### vs. Password Managers (pass, KeePassXC, 1Password, Bitwarden)

Password managers store and retrieve secrets. cryptkey derives a cryptographic key.

| | cryptkey | pass/gopass | KeePassXC | 1Password/Bitwarden |
|---|---|---|---|---|
| **Purpose** | Derive encryption key | Store passwords | Store passwords | Store passwords |
| **Stores secrets** | No (derives on demand) | Yes (GPG-encrypted files) | Yes (database file) | Yes (cloud vault) |
| **Server** | No | No | No | Yes |
| **Threshold auth** | Yes | No | No (password + optional YubiKey) | No |
| **Hardware token** | FIDO2, TPM | No | YubiKey challenge-response | WebAuthn for login |
| **Output** | Raw key bytes | Plaintext password | Plaintext password | Plaintext password |

**Choose a password manager** for storing and recalling passwords. **Choose cryptkey** when you need to derive a stable encryption key from multi-factor authentication without storing the key anywhere.

### vs. Secret Sharing Tools (ssss, Horcrux)

These tools implement Shamir's Secret Sharing directly on secrets or files.

| | cryptkey | ssss | Horcrux |
|---|---|---|---|
| **Shares are** | Encrypted by auth providers, stored locally | Raw text, distributed to people | File fragments, distributed |
| **Reconstruction** | Authenticate with providers | Collect shares from people | Collect file fragments |
| **Share storage** | Single TOML profile on your machine | Each holder stores their share | Each holder stores their fragment |
| **Auth required** | Yes (FIDO2, passphrase, etc. per share) | No (possessing the share is enough) | No (possessing the fragment is enough) |
| **Key derivation** | Built-in (HKDF) | Manual | No (file reconstruction only) |

**Choose ssss/Horcrux** for distributing shares to multiple people or locations. **Choose cryptkey** when one person wants threshold security across their own authentication devices.

### vs. systemd-cryptenroll / fido2-hmac-secret

These tools use hardware tokens for disk encryption or key derivation, but without threshold schemes.

| | cryptkey | systemd-cryptenroll | fido2-hmac-secret |
|---|---|---|---|
| **Multiple unlock methods** | Yes (threshold: need K of N) | Yes (OR: any one works) | No (single token) |
| **Scope** | General key derivation | LUKS volumes only | Raw key output |
| **Lost token recovery** | Other providers meet threshold | Must have enrolled another method | No recovery |
| **Provider types** | FIDO2, passkeys, passphrase, SSH, TPM, recovery | FIDO2, TPM2, PKCS#11, recovery | FIDO2 only |

**Choose systemd-cryptenroll** for LUKS-specific multi-method unlock. **Choose cryptkey** for general-purpose threshold key derivation with built-in resilience to lost devices.

## What Makes cryptkey Different

No other tool combines all three of these properties:

1. **Threshold key derivation** -- not just splitting a secret, but reconstructing a key only when enough providers authenticate
2. **Diverse auth providers** -- each share is protected by a different authentication method (FIDO2 hmac-secret, passkey WebAuthn, Argon2 passphrase, SSH signatures, TPM2, recovery codes)
3. **Fully local** -- no server, no cloud, no network; a single binary and a TOML profile

The closest alternatives each lack one dimension:

- **age-plugin-sss** has threshold + local, but limited auth provider diversity
- **HashiCorp Vault** has threshold + diverse auth, but requires a server
- **systemd-cryptenroll** has diverse auth + local, but uses OR logic instead of threshold
